use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

use crate::common::is_other;

const ATOMIC_CANDIDATE_TYPES: &[&str] = &[
    "bool", "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64", "isize", "usize",
];

fn base_name(node: &AstNode) -> &str {
    node.text().rsplit("::").next().unwrap_or(node.text())
}

/// The sole primitive type argument of `Mutex<T>`, if `T` is a single bare
/// primitive (not `Mutex<()>`, not `Mutex<(bool, bool)>`, not a generic
/// struct field, ...).
fn sole_primitive_type_arg(generic_type: &AstNode) -> Option<&AstNode> {
    let type_args = generic_type
        .children()
        .iter()
        .find(|c| is_other(c.kind(), "type_arguments"))?;
    let args: Vec<_> = type_args
        .children()
        .iter()
        .filter(|c| !is_other(c.kind(), "lifetime"))
        .collect();
    let [arg] = args.as_slice() else { return None };
    is_other(arg.kind(), "primitive_type").then_some(*arg)
}

/// `std::sync::atomic` has a lock-free `AtomicBool`/`AtomicU32`/... for every
/// primitive integer and `bool`. A `Mutex` wrapping nothing but one of these
/// pays for locking, blocking, and poisoning to protect a value that could
/// instead be updated with a single atomic instruction.
pub struct MutexAtomicCandidateRule {
    id: RuleId,
}

impl MutexAtomicCandidateRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:mutex-atomic-candidate").expect("valid rule id"),
        }
    }
}

impl Default for MutexAtomicCandidateRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MutexAtomicCandidateRule {
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
            description: "`Mutex<T>` where `T` is `bool` or a primitive integer pays for \
                locking to protect a value `std::sync::atomic` can update lock-free; prefer \
                `AtomicBool`/`AtomicU32`/etc."
                .into(),
            tags: vec!["performance".into(), "rust".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let test_ranges = vord_rules_engine::rust_test_module_ranges(file.content());

        ast.descendants()
            .filter(|n| is_other(n.kind(), "generic_type"))
            .filter(|n| {
                n.first_child()
                    .is_some_and(|base| base_name(base) == "Mutex")
            })
            .filter(|n| !vord_rules_engine::in_ranges(&test_ranges, n.span().start_line))
            .filter_map(|n| {
                let arg = sole_primitive_type_arg(n)?;
                ATOMIC_CANDIDATE_TYPES.contains(&arg.text()).then(|| {
                    Finding::new(
                        format!(
                            "`Mutex<{}>` could be a lock-free `Atomic{}` instead",
                            arg.text(),
                            atomic_suffix(arg.text())
                        ),
                        n.span(),
                    )
                })
            })
            .collect()
    }
}

fn atomic_suffix(primitive: &str) -> String {
    if primitive == "bool" {
        "Bool".to_string()
    } else {
        let (sign, width) = primitive.split_at(1);
        format!("{}{}", sign.to_ascii_uppercase(), width)
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.rs", code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        MutexAtomicCandidateRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_mutex_bool() {
        let findings = check("fn f() { let m: Mutex<bool> = Mutex::new(false); }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_mutex_u32_field() {
        let findings = check("struct S { counter: Mutex<u32> }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn flags_qualified_std_sync_mutex() {
        let findings = check("struct S { flag: std::sync::Mutex<bool> }\n");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn ignores_mutex_unit() {
        assert!(check("fn f() { let m: Mutex<()> = Mutex::new(()); }\n").is_empty());
    }

    #[test]
    fn ignores_mutex_struct() {
        assert!(check("struct S { data: Mutex<MyState> }\n").is_empty());
    }

    #[test]
    fn ignores_mutex_string() {
        assert!(check("struct S { name: Mutex<String> }\n").is_empty());
    }

    #[test]
    fn ignores_rwlock_bool() {
        assert!(check("struct S { flag: RwLock<bool> }\n").is_empty());
    }

    #[test]
    fn ignores_mutex_atomic_candidate_inside_a_cfg_test_module() {
        let code = "fn prod() {}\n\n#[cfg(test)]\nmod tests {\n    struct S { counter: Mutex<u32> }\n}\n";
        assert!(check(code).is_empty());
    }
}
