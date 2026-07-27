//! Rule: flags a bare `except:` clause. It catches every `BaseException`,
//! including `SystemExit` and `KeyboardInterrupt`, silently intercepting
//! signals the program should normally propagate (Ctrl-C, `sys.exit`).

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

fn is_except_clause(node: &AstNode) -> bool {
    matches!(node.kind(), NodeKind::Other(name) if name.as_ref() == "except_clause")
}

fn is_bare(except_clause: &AstNode) -> bool {
    let children = except_clause.children();
    children.len() == 1 && matches!(children[0].kind(), NodeKind::Other(name) if name.as_ref() == "block")
}

pub struct BareExceptRule {
    id: RuleId,
}

impl BareExceptRule {
    pub fn new() -> Self {
        Self { id: RuleId::new("python:bare-except").expect("valid rule id") }
    }
}

impl Default for BareExceptRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BareExceptRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> yunq_rules_engine::RuleMetadata {
        yunq_rules_engine::RuleMetadata {
            description: "A bare `except:` also catches `SystemExit` and `KeyboardInterrupt`; name the exception types you actually intend to handle, or use `except Exception:`.".into(),
            tags: vec!["bug".into(), "error-handling".into()],
            cwe: Some(396),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| is_except_clause(n))
            .filter(|n| is_bare(n))
            .map(|n| Finding::new("bare `except:` catches every exception including SystemExit and KeyboardInterrupt", n.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = yunq_parser_python::PythonParser::new().parse(&file).unwrap();
        BareExceptRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_bare_except() {
        assert_eq!(findings("try:\n    f()\nexcept:\n    pass\n").len(), 1);
    }

    #[test]
    fn allows_typed_except() {
        assert!(findings("try:\n    f()\nexcept ValueError:\n    pass\n").is_empty());
    }

    #[test]
    fn allows_broad_but_named_except() {
        assert!(findings("try:\n    f()\nexcept Exception:\n    pass\n").is_empty());
    }
}
