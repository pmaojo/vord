//! Rule: Non-Lexical Lifetimes (NLL) borrow checking rule utilizing `vord_taint::PoloniusEngine`.

use std::collections::{HashMap, HashSet};
use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
use vord_rules_engine::{Finding, Rule, RuleId, Severity};
use vord_taint::{BorrowCheckFacts, Loan, Origin, PoloniusEngine};

pub struct NllBorrowCheckRule {
    id: RuleId,
}

impl NllBorrowCheckRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:nll-borrow-check").expect("valid RuleId"),
        }
    }
}

impl Default for NllBorrowCheckRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NllBorrowCheckRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::rust()
    }

    fn check(&self, _file: &SourceFile, root: &AstNode) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut loans = Vec::new();
        let mut loan_issued_at = HashMap::new();
        let mut origins = HashMap::new();

        // Perform AST scan for borrow sites (&mut x)
        let mut loan_id = 1;
        walk_borrow_sites(
            root,
            &mut loan_id,
            &mut loans,
            &mut loan_issued_at,
            &mut origins,
        );

        let facts = BorrowCheckFacts {
            loans,
            loan_issued_at,
            origins,
        };

        let violations = PoloniusEngine::check(&facts);
        for v in violations {
            findings.push(Finding::new(
                format!("Non-Lexical Lifetimes (NLL) borrow violation: path `{}` has an active loan while invalidated", v.path),
                root.span(),
            ));
        }

        findings
    }
}

fn walk_borrow_sites(
    node: &AstNode,
    loan_id: &mut usize,
    loans: &mut Vec<Loan>,
    loan_issued_at: &mut HashMap<usize, Vec<Loan>>,
    origins: &mut HashMap<Origin, HashSet<usize>>,
) {
    if node.text().contains("&mut ") {
        let path = node.text().trim_start_matches("&mut ").to_string();
        let loan = Loan {
            id: *loan_id,
            path: path.clone(),
            issued_at: 1,
        };
        *loan_id += 1;
        loans.push(loan.clone());
        loan_issued_at.entry(1).or_default().push(loan);

        let mut points = HashSet::new();
        points.insert(1);
        origins.insert(Origin { name: path }, points);
    }

    for child in node.children() {
        walk_borrow_sites(child, loan_id, loans, loan_issued_at, origins);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_nll_borrow_rules() {
        let loans = vec![Loan {
            id: 1,
            path: "x".into(),
            issued_at: 1,
        }];
        let mut loan_issued_at = HashMap::new();
        loan_issued_at.insert(2, loans.clone());

        let mut origins = HashMap::new();
        let mut live = HashSet::new();
        live.insert(2);
        origins.insert(Origin { name: "x".into() }, live);

        let facts = BorrowCheckFacts {
            loans,
            loan_issued_at,
            origins,
        };

        let violations = PoloniusEngine::check(&facts);
        assert!(!violations.is_empty());
    }
}
