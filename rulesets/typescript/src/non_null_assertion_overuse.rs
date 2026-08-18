//! Rule: flags a chained non-null assertion like `foo!.bar!.baz!` — three or
//! more `!` operators stacked in a single member-access chain. Each `!`
//! tells the type checker "trust me, this isn't null" with no runtime
//! check backing the claim; stacking several in one chain is an
//! unambiguous sign the underlying types (or a missing guard) need fixing,
//! not more assertions.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

use crate::common::is_other;

const CHAIN_THRESHOLD: u32 = 3;

/// How many `non_null_expression` nodes are stacked starting at `node`,
/// descending through the `member_expression` chain it wraps. Only counts
/// *this* node's own downward chain, so an outer node in a long chain
/// reports the full length while each inner node reports a shorter one —
/// which means only the outermost node of a chain crosses the threshold,
/// and callers scanning every node in the tree never double-report one
/// chain.
fn chain_len(node: &AstNode) -> u32 {
    if !is_other(node, "non_null_expression") {
        return 0;
    }
    let inner = match node.children() {
        [only] => only,
        _ => return 1,
    };
    let next = if *inner.kind() == NodeKind::MemberAccess {
        inner.first_child().map(chain_len).unwrap_or(0)
    } else {
        chain_len(inner)
    };
    1 + next
}

/// Walks the tree, flagging the outermost node of each chain whose length
/// crosses [`CHAIN_THRESHOLD`] and not descending further into it — a chain
/// already reported has no separately-interesting shorter chain nested
/// inside it, and this avoids reporting the same stack of `!` twice (once
/// from the full chain, once from a 3-deep prefix of a longer one).
fn collect(node: &AstNode, out: &mut Vec<Finding>) {
    if chain_len(node) >= CHAIN_THRESHOLD {
        out.push(Finding::new(
            "this chain stacks 3+ non-null assertions (`!`); fix the underlying types or add a real guard instead",
            node.span(),
        ));
        return;
    }
    for child in node.children() {
        collect(child, out);
    }
}

pub struct NonNullAssertionOveruseRule {
    id: RuleId,
}

impl NonNullAssertionOveruseRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:non-null-assertion-overuse").expect("valid rule id"),
        }
    }
}

impl Default for NonNullAssertionOveruseRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NonNullAssertionOveruseRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Three or more `!` non-null assertions stacked in one member-access chain assert away nullability repeatedly instead of fixing the underlying types or adding a real guard.".into(),
            tags: vec!["typescript".into(), "type-safety".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        collect(ast, &mut findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        NonNullAssertionOveruseRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_triple_chained_assertion() {
        assert_eq!(check("const v = foo!.bar!.baz!;\n").len(), 1);
    }

    #[test]
    fn flags_only_once_for_one_chain() {
        assert_eq!(check("const v = a!.b!.c!.d!;\n").len(), 1);
    }

    #[test]
    fn allows_double_chained_assertion() {
        assert!(check("const v = foo!.bar!;\n").is_empty());
    }

    #[test]
    fn allows_single_assertion() {
        assert!(check("const v = foo!;\n").is_empty());
    }

    #[test]
    fn allows_two_separate_single_assertions() {
        assert!(check("const a = foo!;\nconst b = bar!;\n").is_empty());
    }

    #[test]
    fn flags_two_independent_triple_chains() {
        let code = "const a = x!.y!.z!;\nconst b = p!.q!.r!;\n";
        assert_eq!(check(code).len(), 2);
    }
}
