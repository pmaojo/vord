//! Rule: Microsoft Maintainability Index & Halstead Software Science Metrics Suite (`smells:maintainability-index`).
//! Implements Halstead Volume, Difficulty, Effort, Estimated Bugs (B), Implementation Time (T),
//! and normalized Microsoft Maintainability Index (MI_norm) with language-specific AST classification.

use std::collections::HashMap;
use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

declare_rule_id!(HalsteadMiRule, "smells:maintainability-index");

#[derive(Debug, Clone)]
pub struct HalsteadMiConfig {
    pub threshold_warning: f64,
    pub threshold_error: f64,
}

impl Default for HalsteadMiConfig {
    fn default() -> Self {
        Self {
            threshold_warning: 20.0,
            threshold_error: 10.0,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct HalsteadMetrics {
    pub n1: u32,
    pub n2: u32,
    pub total_n1: u32,
    pub total_n2: u32,
    pub volume: f64,
    pub difficulty: f64,
    pub effort: f64,
    pub estimated_bugs: f64,
    pub time_seconds: f64,
    pub mi: f64,
    pub mi_normalized: f64,
}

impl Rule for HalsteadMiRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, _language: &LanguageIdentifier) -> bool {
        true
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        let config = HalsteadMiConfig::default();
        let loc = file.content().lines().count() as u32;
        let metrics = calculate_halstead_mi(ast, loc);

        if metrics.mi_normalized < config.threshold_error {
            findings.push(Finding::new(
                format!(
                    "Critical Maintainability Index: `{:.1}/100` (threshold = {:.1}). High structural risk: Halstead Volume = {:.0}, Effort = {:.0}, Est. Bugs = {:.2}, Est. Time = {:.1}m.",
                    metrics.mi_normalized, config.threshold_error, metrics.volume, metrics.effort, metrics.estimated_bugs, metrics.time_seconds / 60.0
                ),
                ast.span(),
            ));
        } else if metrics.mi_normalized < config.threshold_warning {
            findings.push(Finding::new(
                format!(
                    "Low Maintainability Index: `{:.1}/100` (threshold = {:.1}). Consider refactoring complex functions (Est. Bugs = {:.2}).",
                    metrics.mi_normalized, config.threshold_warning, metrics.estimated_bugs
                ),
                ast.span(),
            ));
        }

        findings
    }
}

pub fn calculate_halstead_mi(ast: &AstNode, loc: u32) -> HalsteadMetrics {
    let mut operators: HashMap<String, u32> = HashMap::new();
    let mut operands: HashMap<String, u32> = HashMap::new();

    fn walk(node: &AstNode, ops: &mut HashMap<String, u32>, opnds: &mut HashMap<String, u32>) {
        let kind_str = match node.kind() {
            NodeKind::Other(k) => k.as_ref(),
            _ => "",
        };

        // Skip imports and comments
        if kind_str.contains("comment") || kind_str == "use_declaration" || kind_str == "import_statement" {
            return;
        }

        if is_operator(kind_str) {
            *ops.entry(kind_str.to_string()).or_insert(0) += 1;
        } else if is_operand(kind_str) {
            let text = node.text().trim().to_string();
            if !text.is_empty() {
                *opnds.entry(text).or_insert(0) += 1;
            }
        }

        for child in node.children() {
            walk(child, ops, opnds);
        }
    }

    walk(ast, &mut operators, &mut operands);

    let n1 = operators.len() as u32;
    let n2 = operands.len() as u32;
    let total_n1: u32 = operators.values().sum();
    let total_n2: u32 = operands.values().sum();

    let n_total = (n1 + n2).max(1) as f64;
    let big_n = (total_n1 + total_n2) as f64;

    let volume = big_n * n_total.log2();
    let difficulty = (n1 as f64 / 2.0) * (total_n2 as f64 / n2.max(1) as f64);
    let effort = difficulty * volume;
    let estimated_bugs = volume / 3000.0;
    let time_seconds = effort / 18.0;

    // McCabe's M, derived from the real control flow graph (`E − N + 2`,
    // `yunq_cfg::ControlFlowGraph::cyclomatic_complexity`) instead of the
    // syntactic `n1 + N1/4` operator proxy the original formula fell back
    // on. Building the CFG over the whole file yields exactly `1 + total
    // decision points` across every function — the "program complexity"
    // term the Microsoft MI formula's `M` parameter is defined to be.
    let cyclomatic = yunq_cfg::ControlFlowGraph::build(ast).cyclomatic_complexity() as f64;
    let loc_safe = (loc as f64).max(1.0);

    let mi = 171.0 - 5.2 * volume.max(1.0).ln() - 0.23 * cyclomatic - 16.2 * loc_safe.ln();
    let mi_normalized = (mi * 100.0 / 171.0).clamp(0.0, 100.0);

    HalsteadMetrics {
        n1,
        n2,
        total_n1,
        total_n2,
        volume,
        difficulty,
        effort,
        estimated_bugs,
        time_seconds,
        mi,
        mi_normalized,
    }
}

fn is_operator(kind: &str) -> bool {
    matches!(
        kind,
        "binary_expression"
            | "unary_expression"
            | "assignment_expression"
            | "compound_assignment_expr"
            | "call_expression"
            | "index_expression"
            | "if_statement"
            | "if_expression"
            | "for_statement"
            | "while_statement"
            | "switch_statement"
            | "catch_clause"
            | "+"
            | "-"
            | "*"
            | "/"
            | "&&"
            | "||"
            | "=="
            | "!="
            | "<"
            | ">"
            | "<="
            | ">="
    )
}

fn is_operand(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "integer_literal"
            | "float_literal"
            | "string_literal"
            | "number"
            | "string"
            | "boolean_literal"
            | "property_identifier"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::LanguageIdentifier;
    use yunq_parser_typescript::TypeScriptParser;
    use yunq_rules_engine::AstParser;

    #[test]
    fn test_simple_function_has_high_mi() {
        let code = r#"
        function sum(a: number, b: number): number {
            return a + b;
        }
        "#;
        let file = SourceFile::new("src/sum.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        let metrics = calculate_halstead_mi(&ast, 5);
        assert!(metrics.mi_normalized > 50.0, "Simple function should have high MI");
    }
}
