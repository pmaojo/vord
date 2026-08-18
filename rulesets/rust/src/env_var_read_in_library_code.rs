use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_env_var_call(callee_text: &str) -> bool {
    callee_text.ends_with("env::var") || callee_text.ends_with("env::var_os")
}

fn fn_name(fn_node: &AstNode) -> Option<&str> {
    fn_node
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::Identifier)
        .map(AstNode::text)
}

/// Collects `env::var`/`env::var_os` calls in `node`, tracking whether the
/// walk is currently inside a named function called `main`: a closure
/// (`NodeKind::FunctionDef` with no leading name) inherits the enclosing
/// context, but entering any other named function resets it — reading an
/// env var from a helper function called *from* `main` is exactly the
/// "buried in library logic" shape this rule targets.
fn collect<'a>(node: &'a AstNode, in_main: bool, out: &mut Vec<&'a AstNode>) {
    for child in node.children() {
        let child_in_main = if *child.kind() == NodeKind::FunctionDef {
            match fn_name(child) {
                Some(name) => name == "main",
                None => in_main, // closure: inherits the enclosing context
            }
        } else {
            in_main
        };

        if !child_in_main
            && *child.kind() == NodeKind::Call
            && child
                .first_child()
                .is_some_and(|c| is_env_var_call(c.text()))
        {
            out.push(child);
        }
        collect(child, child_in_main, out);
    }
}

/// Reading environment variables deep inside library logic (rather than
/// once, at the composition root) makes the function's real dependencies
/// invisible from its signature, complicates testing (every caller now
/// needs the right process environment instead of passing a value), and
/// scatters what should be one place to reason about configuration across
/// the whole codebase. Read the variable in `main` (or an explicit config
/// struct built there) and pass the value down instead.
pub struct EnvVarReadInLibraryCodeRule {
    id: RuleId,
}

impl EnvVarReadInLibraryCodeRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:env-var-read-in-library-code").expect("valid rule id"),
        }
    }
}

impl Default for EnvVarReadInLibraryCodeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for EnvVarReadInLibraryCodeRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::rust()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        15
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "Reading environment variables deep inside library logic hides the \
                function's real dependencies and complicates testing. Read configuration once \
                at the composition root (`main`, or a config struct built there) and pass the \
                value down."
                .into(),
            tags: vec!["maintainability".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let path = file.path();
        if path.contains("src/bin/") || path.ends_with("main.rs") || path.contains("/bin/") {
            return Vec::new();
        }

        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());
        let mut calls = Vec::new();
        collect(ast, false, &mut calls);

        calls
            .into_iter()
            .filter(|call| !vord_rules_engine::in_ranges(&test_ranges, call.span().start_line))
            .map(|call| {
                Finding::new(
                    "reading an environment variable here, outside `main`/the composition \
                    root, hides this function's real dependencies; read it once at startup \
                    and pass the value down"
                        .to_string(),
                    call.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        check_with_path("src/lib.rs", code)
    }

    fn check_with_path(path: &str, code: &str) -> Vec<Finding> {
        let file = SourceFile::new(path, code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        EnvVarReadInLibraryCodeRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_env_var_in_library_function() {
        let findings = check("fn connect() { let _ = std::env::var(\"DATABASE_URL\"); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_env_var_in_closure_called_from_a_non_main_function() {
        let findings = check("fn build() { let f = || std::env::var(\"X\"); f().unwrap(); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_env_var_in_main() {
        assert!(check("fn main() { let _ = std::env::var(\"DATABASE_URL\"); }\n").is_empty());
    }

    #[test]
    fn ignores_env_var_in_closure_inside_main() {
        assert!(check("fn main() { let f = || std::env::var(\"X\"); f().unwrap(); }\n").is_empty());
    }

    #[test]
    fn ignores_env_var_in_bin_crate_file() {
        assert!(
            check_with_path(
                "src/bin/worker.rs",
                "fn connect() { let _ = std::env::var(\"X\"); }\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_env_var_in_main_rs() {
        assert!(
            check_with_path(
                "src/main.rs",
                "fn connect() { let _ = std::env::var(\"X\"); }\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn ignores_env_var_read_in_library_code_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let _ = std::env::var(\"X\");\n    }\n}\n";
        assert!(check(code).is_empty());
    }
}
