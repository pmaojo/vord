//! Rule: a class/struct with an excessive number of methods and/or fields —
//! the classic "God Class" smell, doing far more than a single
//! responsibility should. Doesn't need symbol/type resolution (just a
//! member count), but reuses `yunq_symbols::ClassRegistry` for the
//! class/struct extraction itself rather than re-parsing class shapes a
//! second time — the same extraction `smells:feature-envy` and
//! `smells:refused-bequest` need.
//!
//! Whole-program (`CrossFileRule`, same wiring pattern as
//! `owasp:cross-file-injection`): built via `ClassRegistry::build_cross_file`
//! over every analyzed file so a Rust struct's methods, commonly split across
//! `impl` blocks in other files, are all counted against the one struct
//! rather than only whichever file happens to declare it.

use yunq_ast::{AstNode, SourceFile};
use yunq_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use yunq_symbols::ClassRegistry;

pub struct GodClassRule {
    id: RuleId,
    max_methods: usize,
    max_fields: usize,
}

impl GodClassRule {
    pub fn new(max_methods: usize, max_fields: usize) -> Self {
        Self {
            id: RuleId::new("smells:god-class").expect("valid rule id"),
            max_methods,
            max_fields,
        }
    }
}

impl Default for GodClassRule {
    /// "Too many methods"/"too many fields" checks conventionally default in
    /// this range; picked here as a single combined threshold rather than
    /// two separate rules.
    fn default() -> Self {
        Self::new(20, 15)
    }
}

impl CrossFileRule for GodClassRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A class/struct with an excessive number of methods and/or fields is doing too much — split it along its actual responsibilities.".into(),
            tags: vec!["design".into(), "god-class".into(), "cross-file".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let views: Vec<(&str, &AstNode)> =
            files.iter().map(|(file, ast)| (file.path(), ast)).collect();
        let registry = ClassRegistry::build_cross_file(&views);
        registry
            .iter()
            .filter_map(|class| {
                let too_many_methods = class.methods.len() > self.max_methods;
                let too_many_fields = class.fields.len() > self.max_fields;
                if !too_many_methods && !too_many_fields {
                    return None;
                }
                let span = class.span?;
                let index = files.iter().position(|(file, _)| file.path() == class.file)?;
                Some((
                    index,
                    Finding::new(
                        format!(
                            "`{}` has {} methods (max {}) and {} fields (max {}) — likely doing too much; split it along its actual responsibilities",
                            class.name,
                            class.methods.len(),
                            self.max_methods,
                            class.fields.len(),
                            self.max_fields
                        ),
                        span,
                    ),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::LanguageIdentifier;
    use yunq_rules_engine::AstParser;

    fn check_ts(code: &str, max_methods: usize, max_fields: usize) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        GodClassRule::new(max_methods, max_fields)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect()
    }

    fn method_block(n: usize) -> String {
        (0..n).map(|i| format!("  m{i}() {{}}\n")).collect()
    }

    #[test]
    fn flags_class_with_too_many_methods() {
        let code = format!("class Big {{\n{}}}\n", method_block(5));
        let findings = check_ts(&code, 3, 100);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Big"));
        assert!(findings[0].message.contains("5 methods"));
    }

    #[test]
    fn flags_class_with_too_many_fields() {
        let fields: String = (0..5).map(|i| format!("  f{i}: number = {i};\n")).collect();
        let code = format!("class Big {{\n{fields}}}\n");
        let findings = check_ts(&code, 100, 3);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("5 fields"));
    }

    #[test]
    fn allows_small_class() {
        let code = "class Small {\n  m1() {}\n  f1: number = 1;\n}\n";
        let findings = check_ts(code, 20, 15);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_rust_struct_with_too_many_methods_across_impl_blocks() {
        let code = format!(
            "struct Big {{ x: i32 }}\nimpl Big {{\n{}}}\n",
            (0..5)
                .map(|i| format!("  fn m{i}(&self) {{}}\n"))
                .collect::<String>()
        );
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = yunq_parser_rust::RustParser::new().parse(&file).unwrap();
        let files = vec![(file, ast)];
        let findings: Vec<Finding> = GodClassRule::new(3, 100)
            .check(&files)
            .into_iter()
            .map(|(_, f)| f)
            .collect();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("Big"));
    }

    #[test]
    fn flags_rust_struct_whose_methods_come_from_an_impl_in_a_different_file() {
        let struct_file = SourceFile::new(
            "s.rs",
            "struct Big { x: i32 }\n",
            LanguageIdentifier::rust(),
        )
        .unwrap();
        let impl_code = format!(
            "impl Big {{\n{}}}\n",
            (0..5)
                .map(|i| format!("  fn m{i}(&self) {{}}\n"))
                .collect::<String>()
        );
        let impl_file = SourceFile::new("i.rs", impl_code, LanguageIdentifier::rust()).unwrap();
        let parser = yunq_parser_rust::RustParser::new();
        let files = vec![
            (struct_file.clone(), parser.parse(&struct_file).unwrap()),
            (impl_file.clone(), parser.parse(&impl_file).unwrap()),
        ];
        let findings = GodClassRule::new(3, 100).check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        // Finding is attached to the struct's own file, not the impl's.
        assert_eq!(files[*index].0.path(), "s.rs");
        assert!(finding.message.contains("Big"));
        assert!(finding.message.contains("5 methods"));
    }
}
