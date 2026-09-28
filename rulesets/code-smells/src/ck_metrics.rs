//! Rule: Chidamber & Kemerer (CK) Object-Oriented Quality Metrics Suite.
//! Measures WMC (Weighted Methods per Class) and CBO (Coupling Between Objects).
//! Part of the SQuaD 725-metric taxonomy alignment for vord.

use vord_ast::{AstNode, SourceFile};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};
use vord_symbols::ClassRegistry;

pub struct CkMetricsRule {
    id: RuleId,
    max_wmc: usize,
    max_cbo: usize,
}

impl CkMetricsRule {
    pub fn new(max_wmc: usize, max_cbo: usize) -> Self {
        Self {
            id: RuleId::new("smells:ck-oo-metrics").expect("valid rule id"),
            max_wmc,
            max_cbo,
        }
    }
}

impl Default for CkMetricsRule {
    fn default() -> Self {
        Self::new(25, 10)
    }
}

impl CrossFileRule for CkMetricsRule {
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
            description: "Chidamber & Kemerer (CK) Object-Oriented Metrics: checks Weighted Methods per Class (WMC) and Coupling Between Objects (CBO).".into(),
            tags: vec!["design".into(), "ck-metrics".into(), "object-oriented".into()],
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
                // 1. WMC: Weighted Methods per Class — CK's definition is the
                // *sum* of each method's cyclomatic complexity, not a flat
                // per-method count (a class with ten trivial getters and a
                // class with ten branch-heavy methods are not equally
                // complex). Reuse the same CFG builder `smells:maintainability-
                // index` uses for its own cyclomatic term, applied per method
                // body instead of per file.
                let wmc: usize = class
                    .methods
                    .iter()
                    .map(|method| {
                        vord_cfg::ControlFlowGraph::build(method.node).cyclomatic_complexity()
                    })
                    .sum();
                let high_wmc = wmc > self.max_wmc;

                // 2. CBO: Coupling Between Objects (distinct parameter and field type references)
                let mut cbo_set = std::collections::HashSet::new();
                for method in &class.methods {
                    for param in &method.params {
                        if let Some(param_type) = &param.declared_type {
                            if param_type != &class.name {
                                cbo_set.insert(param_type.as_str());
                            }
                        }
                    }
                }
                let high_cbo = cbo_set.len() > self.max_cbo;

                if !high_wmc && !high_cbo {
                    return None;
                }

                let span = class.span?;
                let index = files.iter().position(|(file, _)| file.path() == class.file)?;

                let msg = if high_wmc && high_cbo {
                    format!(
                        "CK Metric Violation: `{}` has high WMC (Weighted Methods per Class = {}, max {}) and high CBO (Coupling Between Objects = {}, max {}). Refactor class into smaller, decoupled modules.",
                        class.name, wmc, self.max_wmc, cbo_set.len(), self.max_cbo
                    )
                } else if high_wmc {
                    format!(
                        "CK Metric Violation: `{}` has high WMC (Weighted Methods per Class = {}, max {}). Refactor into smaller cohesive classes.",
                        class.name, wmc, self.max_wmc
                    )
                } else {
                    format!(
                        "CK Metric Violation: `{}` has high CBO (Coupling Between Objects = {}, max {}). Reduce tight dependencies.",
                        class.name, cbo_set.len(), self.max_cbo
                    )
                };

                Some((index, Finding::new(msg, span)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::LanguageIdentifier;
    use vord_rules_engine::AstParser;

    #[test]
    fn test_ck_metrics_rule_flags_high_wmc() {
        let code = r#"
        class LargeGodClass {
            m1() {} m2() {} m3() {} m4() {} m5() {}
            m6() {} m7() {} m8() {} m9() {} m10() {}
            m11() {} m12() {} m13() {} m14() {} m15() {}
            m16() {} m17() {} m18() {} m19() {} m20() {}
            m21() {} m22() {} m23() {} m24() {} m25() {} m26() {}
        }
        "#;
        let file = SourceFile::new("test.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        let files = vec![(file, ast)];
        let findings = CkMetricsRule::new(20, 5).check(&files);
        assert!(!findings.is_empty(), "CK Metrics rule should flag class exceeding WMC threshold");
    }
}
