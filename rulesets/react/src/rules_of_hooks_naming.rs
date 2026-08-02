//! Rule: flags a function that calls a Hook internally but isn't itself
//! named like a Hook (`useThing`) or a component (`PascalCase`). Naming is
//! how both React and its tooling (including this very rule, and
//! `react:rules-of-hooks-conditional`) tell "this may legally call Hooks"
//! apart from an ordinary helper — a plain-named function calling one is
//! either mis-following the convention or, worse, a helper that only
//! happens to work today because of how it's currently called.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, RuleMetadata, Severity};

use crate::common::{hook_call_name, is_hook_name, own_scope_descendants};

fn calls_a_hook(func: &AstNode) -> bool {
    own_scope_descendants(func)
        .into_iter()
        .any(|n| hook_call_name(n).is_some())
}

/// The declared name of a `function`-keyword form (`function_declaration` /
/// named `function_expression` / generator): its first child is the name
/// identifier directly. Guarded on the `function` keyword so a bare
/// single-parameter arrow (`x => ...`, whose sole child is likewise a plain
/// `Identifier`) is never misread as a named declaration — an arrow
/// function's name, if any, comes from the enclosing `variable_declarator`
/// instead (see [`variable_decl_name`]).
fn declared_name(func: &AstNode) -> Option<&str> {
    if !func.text().trim_start().starts_with("function") {
        return None;
    }
    let first = func.first_child()?;
    (*first.kind() == NodeKind::Identifier).then(|| first.text())
}

/// `const name = (...) => {...}` / `const name = function () {...}`: the
/// name lives on the `VariableDecl`, the function on one of its other
/// children (the initializer).
fn variable_decl_name(decl: &AstNode) -> Option<(&str, &AstNode)> {
    let name = decl
        .first_child()
        .filter(|c| *c.kind() == NodeKind::Identifier)?
        .text();
    let func = decl
        .children()
        .iter()
        .find(|c| *c.kind() == NodeKind::FunctionDef)?;
    Some((name, func))
}

fn check_naming(name: &str, func: &AstNode, findings: &mut Vec<Finding>) {
    if !calls_a_hook(func) {
        return;
    }
    let looks_like_hook = is_hook_name(name);
    let looks_like_component = name.chars().next().is_some_and(|c| c.is_ascii_uppercase());
    if !looks_like_hook && !looks_like_component {
        findings.push(Finding::new(
            format!(
                "`{name}` calls a React Hook but its name doesn't start with `use`; \
                 rename it (e.g. `use{first_upper}...`) so callers and lint tooling can \
                 tell it follows the rules of Hooks",
                first_upper = name.get(0..1).unwrap_or("").to_ascii_uppercase(),
            ),
            func.span(),
        ));
    }
}

pub struct RulesOfHooksNamingRule {
    id: RuleId,
}

impl RulesOfHooksNamingRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("react:rules-of-hooks-naming").expect("valid rule id"),
        }
    }
}

impl Default for RulesOfHooksNamingRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for RulesOfHooksNamingRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "A function calls a React Hook internally but is named neither like a Hook (`useThing`) nor a component (`PascalCase`), so it isn't recognizable as somewhere Hooks may legally be called.".into(),
            tags: vec!["react".into(), "rules-of-hooks".into(), "convention".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        for node in ast.descendants() {
            if *node.kind() == NodeKind::FunctionDef {
                if let Some(name) = declared_name(node) {
                    check_naming(name, node, &mut findings);
                }
            } else if *node.kind() == NodeKind::VariableDecl {
                if let Some((name, func)) = variable_decl_name(node) {
                    check_naming(name, func, &mut findings);
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.tsx", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        RulesOfHooksNamingRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_lowercase_function_declaration_calling_a_hook() {
        let findings = check("function fetchStuff() {\n    useEffect(() => {}, []);\n}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("fetchStuff"));
    }

    #[test]
    fn flags_lowercase_arrow_function_calling_a_hook() {
        let findings =
            check("const fetchStuff = () => {\n    const [x] = useState(0);\n    return x;\n};\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("fetchStuff"));
    }

    #[test]
    fn allows_hook_named_function() {
        let findings = check("function useThing() {\n    useEffect(() => {}, []);\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn allows_component_named_function() {
        let findings =
            check("function Widget() {\n    useEffect(() => {}, []);\n    return null;\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_functions_that_call_no_hook() {
        let findings = check("function helper() {\n    doSomething();\n}\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_mistake_a_bare_arrow_parameter_for_a_declared_name() {
        // `x` is `useThing`'s single unparenthesized parameter, not a
        // function name — must not be flagged as "calls a hook but isn't
        // named like one".
        let findings = check("list.forEach(x => {\n    useState(x);\n});\n");
        assert!(findings.is_empty());
    }
}
