use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(ComponentPascalCaseRule, "naming:component-pascal-case");

impl Rule for ComponentPascalCaseRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        // If file is a .tsx / component file, check filename
        let path = file.path();
        if path.ends_with(".tsx") {
            let name = path.split(['/', '\\']).next_back().unwrap_or("").trim_end_matches(".tsx");
            if !name.is_empty() && name != "index" && name != "App" && !is_pascal_case(name) {
                findings.push(Finding::new(
                    format!("React component file `{}` should be named using `PascalCase` (e.g. `UserProfile.tsx`).", name),
                    ast.span(),
                ));
            }
        }

        fn walk(node: &AstNode, out: &mut Vec<Finding>) {
            if *node.kind() == NodeKind::FunctionDef {
                if let Some(id_node) = node.children().iter().find(|c| *c.kind() == NodeKind::Identifier) {
                    let fn_name = id_node.text();
                    // If function returns JSX (checked simply via text containing JSX elements)
                    let text = node.text();
                    if (text.contains("return <") || text.contains("return ( <") || text.contains("return ("))
                        && fn_name.chars().next().is_some_and(|c| c.is_lowercase())
                        && !fn_name.starts_with("use")
                    {
                        out.push(Finding::new(
                            format!("React component function `{}` should use `PascalCase`.", fn_name),
                            id_node.span(),
                        ));
                    }
                }
            }
            for child in node.children() {
                walk(child, out);
            }
        }

        walk(ast, &mut findings);
        findings
    }
}

fn is_pascal_case(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) if first.is_uppercase() => !s.contains('-') && !s.contains('_'),
        _ => false,
    }
}
