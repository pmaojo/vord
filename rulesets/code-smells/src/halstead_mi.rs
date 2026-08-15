//! Rule: Microsoft Maintainability Index & Halstead Software Science Metrics Suite (`smells:maintainability-index`).
//! Implements Halstead Volume, Difficulty, Effort, Estimated Bugs (B), Implementation Time (T),
//! and normalized Microsoft Maintainability Index (MI_norm) with language-specific AST classification.

use std::collections::HashMap;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity, declare_rule_id};

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
        let loc = effective_loc(file.content(), ast);
        let metrics = calculate_halstead_mi(ast, loc);
        let breakdown = worst_function_breakdown(ast);

        if metrics.mi_normalized < config.threshold_error {
            findings.push(Finding::new(
                format!(
                    "Critical Maintainability Index: `{:.1}/100` (threshold = {:.1}). High structural risk: Halstead Volume = {:.0}, Effort = {:.0}, Est. Bugs = {:.2}, Est. Time = {:.1}m.{}",
                    metrics.mi_normalized, config.threshold_error, metrics.volume, metrics.effort, metrics.estimated_bugs, metrics.time_seconds / 60.0, breakdown
                ),
                ast.span(),
            ));
        } else if metrics.mi_normalized < config.threshold_warning {
            findings.push(Finding::new(
                format!(
                    "Low Maintainability Index: `{:.1}/100` (threshold = {:.1}). Consider refactoring complex functions (Est. Bugs = {:.2}).{}",
                    metrics.mi_normalized, config.threshold_warning, metrics.estimated_bugs, breakdown
                ),
                ast.span(),
            ));
        }

        findings
    }
}

/// Lines of code for the MI formula's `ln(LOC)` term, counting only lines
/// that hold actual code — blank lines and lines wholly inside a comment
/// node are excluded. The Coleman et al. formula (and radon's reference
/// implementation) intend `LOC` as a proxy for how much there is to
/// understand, not "how many lines this file spans"; counting comment lines
/// toward it means adding documentation *lowers* the score, which is
/// backwards; two files with identical logic but different comment density
/// should not receive different MI verdicts.
fn effective_loc(source: &str, ast: &AstNode) -> u32 {
    let mut comment_lines: std::collections::HashSet<u32> = std::collections::HashSet::new();

    fn collect_comment_lines(node: &AstNode, lines: &mut std::collections::HashSet<u32>) {
        if matches!(node.kind(), NodeKind::Comment) {
            let span = node.span();
            for line in span.start_line..=span.end_line {
                lines.insert(line);
            }
            return;
        }
        for child in node.children() {
            collect_comment_lines(child, lines);
        }
    }
    collect_comment_lines(ast, &mut comment_lines);

    let effective = source
        .lines()
        .enumerate()
        .filter(|(idx, line)| {
            let line_no = *idx as u32 + 1;
            !line.trim().is_empty() && !comment_lines.contains(&line_no)
        })
        .count() as u32;

    effective.max(1)
}

/// Renders the file's most complex functions (by cyclomatic complexity) as a
/// short suffix on the finding message, so a refactor can target the actual
/// hot spot instead of guessing from a single whole-file number. Capped at 3
/// entries to keep the message scannable; a file with no recognised
/// functions (a top-level script) renders nothing extra.
fn worst_function_breakdown(ast: &AstNode) -> String {
    let mut functions = vord_rules_engine::function_complexities(ast);
    if functions.is_empty() {
        return String::new();
    }
    functions.sort_by(|a, b| b.cyclomatic.cmp(&a.cyclomatic));
    let entries: Vec<String> = functions
        .iter()
        .take(3)
        .map(|f| format!("line {} (cyclomatic = {})", f.span.start_line, f.cyclomatic))
        .collect();
    format!(" Most complex functions: {}.", entries.join(", "))
}

pub fn calculate_halstead_mi(ast: &AstNode, loc: u32) -> HalsteadMetrics {
    let mut operators: HashMap<String, u32> = HashMap::new();
    let mut operands: HashMap<String, u32> = HashMap::new();

    fn walk(node: &AstNode, ops: &mut HashMap<String, u32>, opnds: &mut HashMap<String, u32>) {
        let kind_str = match node.kind() {
            NodeKind::Other(k) => k.as_ref(),
            _ => "",
        };

        // Skip imports and comments. Comments map to the dedicated
        // `NodeKind::Comment` variant, not `NodeKind::Other`, so `kind_str`
        // alone (which is only populated for `Other`) can't see them.
        if matches!(node.kind(), NodeKind::Comment)
            || kind_str == "use_declaration"
            || kind_str == "import_statement"
        {
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

    // McCabe's M, averaged across the file's functions/methods. The Coleman
    // et al. (1994) whitepaper that defines the Microsoft Maintainability
    // Index — and radon's widely-used reference implementation — both treat
    // the module-level `G` term as the *average* extended cyclomatic
    // complexity of the module's blocks, not a file-wide total. Building one
    // CFG over the *whole file* AST (the previous approach here) instead
    // summed decision points across every function in it, so the score fell
    // as more functions were added regardless of how simple each one was —
    // a file with thirty small, well-tested functions scored far worse than
    // one ten-times-as-complex function, which is backwards. A file with no
    // functions at all (a top-level script) falls back to the whole-file
    // CFG, since there is nothing to average.
    let functions = vord_rules_engine::function_complexities(ast);
    let cyclomatic = if functions.is_empty() {
        vord_cfg::ControlFlowGraph::build(ast).cyclomatic_complexity() as f64
    } else {
        let total: u32 = functions.iter().map(|f| f.cyclomatic).sum();
        total as f64 / functions.len() as f64
    };
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
    use vord_ast::LanguageIdentifier;
    use vord_parser_typescript::TypeScriptParser;
    use vord_rules_engine::AstParser;

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

    #[test]
    fn effective_loc_ignores_comments_and_blank_lines() {
        let code = r#"
        // A short doc comment explaining this function in great detail,
        // spanning several lines so the file grows without adding logic.
        // Another line. And another. And one more for good measure.

        function sum(a: number, b: number): number {
            return a + b;
        }
        "#;
        let file = SourceFile::new("src/sum.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        let loc = effective_loc(file.content(), &ast);
        // Only the function signature, its body, and the closing brace hold
        // real code — comment and blank lines must not inflate this.
        assert!(loc <= 3, "comment-only and blank lines should not count toward LOC, got {loc}");
    }

    #[test]
    fn comment_density_does_not_change_mi() {
        let bare = r#"
        function sum(a: number, b: number): number {
            return a + b;
        }
        "#;
        let commented = r#"
        // Adds two numbers together.
        // This is a trivial helper used throughout the codebase.
        function sum(a: number, b: number): number {
            return a + b;
        }
        "#;
        let bare_file = SourceFile::new("src/bare.ts", bare, LanguageIdentifier::typescript()).unwrap();
        let bare_ast = TypeScriptParser::new().parse(&bare_file).unwrap();
        let bare_mi =
            calculate_halstead_mi(&bare_ast, effective_loc(bare_file.content(), &bare_ast));

        let commented_file =
            SourceFile::new("src/commented.ts", commented, LanguageIdentifier::typescript()).unwrap();
        let commented_ast = TypeScriptParser::new().parse(&commented_file).unwrap();
        let commented_mi = calculate_halstead_mi(
            &commented_ast,
            effective_loc(commented_file.content(), &commented_ast),
        );

        assert_eq!(
            bare_mi.mi_normalized, commented_mi.mi_normalized,
            "adding comments alone must not change the MI verdict"
        );
    }

    #[test]
    fn worst_function_breakdown_names_the_most_complex_function() {
        let code = r#"
        function trivial(): number {
            return 1;
        }

        function branchy(x: number): number {
            if (x > 0) {
                if (x > 10) {
                    return 2;
                }
                return 1;
            }
            return 0;
        }
        "#;
        let file = SourceFile::new("src/mixed.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = TypeScriptParser::new().parse(&file).unwrap();
        let breakdown = worst_function_breakdown(&ast);
        assert!(breakdown.contains("Most complex functions"));
        assert!(breakdown.contains("cyclomatic = 3"));
    }
}
