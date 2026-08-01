use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(ModernTypeSyntaxRule, "python:modern-type-syntax");

impl Rule for ModernTypeSyntaxRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Minor
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        5
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "Use modern Python 3.9+ / PEP 585/604 type syntax (`list[T]`, `dict[K, V]`, `T | None`) instead of `typing.List`, `typing.Dict`, `typing.Optional`, `typing.Union`.".into(),
            tags: vec!["python-idiom".into(), "maintainability".into(), "typing".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();

        fn walk<'a>(node: &'a AstNode, out: &mut Vec<Finding>) {
            let text = node.text();
            let kind_str = match node.kind() {
                NodeKind::Other(k) => k.as_ref(),
                _ => "",
            };

            if kind_str == "import_from_statement" {
                if text.contains("from typing import") {
                    for child in node.children() {
                        let c_text = child.text();
                        if c_text == "List" || c_text == "Dict" {
                            out.push(Finding::new(
                                format!("Import of legacy `typing.{c_text}` alias; use built-in collection types instead (PEP 585)."),
                                child.span(),
                            ));
                        } else if c_text == "Optional" || c_text == "Union" {
                            out.push(Finding::new(
                                format!("Import of legacy `typing.{c_text}` alias; use union syntax `|` instead (PEP 604)."),
                                child.span(),
                            ));
                        }
                    }
                }
                return;
            }

            if kind_str == "type" || kind_str == "type_annotation" || *node.kind() == NodeKind::MemberAccess {
                if text.starts_with("typing.List") || text.starts_with("List[") {
                    out.push(Finding::new(
                        "Use built-in `list[T]` instead of `typing.List` (PEP 585).",
                        node.span(),
                    ));
                    return;
                }
                if text.starts_with("typing.Dict") || text.starts_with("Dict[") {
                    out.push(Finding::new(
                        "Use built-in `dict[K, V]` instead of `typing.Dict` (PEP 585).",
                        node.span(),
                    ));
                    return;
                }
                if text.starts_with("typing.Optional") || text.starts_with("Optional[") {
                    out.push(Finding::new(
                        "Use union syntax `T | None` instead of `typing.Optional` (PEP 604).",
                        node.span(),
                    ));
                    return;
                }
                if text.starts_with("typing.Union") || text.starts_with("Union[") {
                    out.push(Finding::new(
                        "Use union operator `A | B` instead of `typing.Union` (PEP 604).",
                        node.span(),
                    ));
                    return;
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

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        ModernTypeSyntaxRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_typing_list_subscript() {
        let findings = check("def foo(x: typing.List[int]) -> None: pass\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("list[T]"));
    }

    #[test]
    fn flags_imported_list_subscript() {
        let findings = check("def foo(x: List[int]) -> None: pass\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("list[T]"));
    }

    #[test]
    fn flags_typing_dict_subscript() {
        let findings = check("a: typing.Dict[str, int] = {}\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("dict[K, V]"));
    }

    #[test]
    fn flags_typing_optional_subscript() {
        let findings = check("b: typing.Optional[str] = None\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("T | None"));
    }

    #[test]
    fn flags_typing_union_subscript() {
        let findings = check("c: typing.Union[int, str] = 1\n");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("A | B"));
    }

    #[test]
    fn flags_imports_from_typing() {
        let findings = check("from typing import List, Dict, Optional, Union\n");
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn allows_modern_syntax() {
        let findings = check("def foo(x: list[int], y: dict[str, int]) -> str | None: pass\n");
        assert!(findings.is_empty());
    }
}
