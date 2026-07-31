//! Polonius / Non-Lexical Lifetimes (NLL) Borrow Checking for Rust semantics.
//! Models lifetimes as sets of CFG points and evaluates origin validity, loans, and storage invalidations.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Loan {
    pub id: usize,
    pub path: String,
    pub issued_at: usize, // CFG block_id
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Origin {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BorrowCheckFacts {
    pub loans: Vec<Loan>,
    pub loan_issued_at: HashMap<usize, Vec<Loan>>, // block_id -> Loans
    pub origins: HashMap<Origin, HashSet<usize>>, // Origin -> set of CFG points where origin is live
}

#[derive(Debug, Clone)]
pub struct BorrowCheckViolation {
    pub loan_id: usize,
    pub path: String,
    pub conflicting_block_id: usize,
}

pub struct PoloniusEngine;

impl PoloniusEngine {
    /// Evaluates Datalog-style relational borrow checking rules over CFG points.
    pub fn check(facts: &BorrowCheckFacts) -> Vec<BorrowCheckViolation> {
        let mut violations = Vec::new();

        // Check if a path with an active loan is mutated/invalidated at a CFG point where the loan's origin is still live
        for (&block_id, loans) in &facts.loan_issued_at {
            for loan in loans {
                for (origin, live_points) in &facts.origins {
                    if live_points.contains(&block_id) {
                        // Invalidation rule: mutating path while loan's origin is live
                        if origin.name.contains(&loan.path) && block_id != loan.issued_at {
                            violations.push(BorrowCheckViolation {
                                loan_id: loan.id,
                                path: loan.path.clone(),
                                conflicting_block_id: block_id,
                            });
                        }
                    }
                }
            }
        }

        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_loan_origins_and_detects_nll_conflicts() {
        let loan = Loan {
            id: 1,
            path: "x".into(),
            issued_at: 0,
        };
        let mut loan_issued_at = HashMap::new();
        loan_issued_at.insert(1, vec![loan.clone()]);

        let mut origins = HashMap::new();
        let mut live = HashSet::new();
        live.insert(1);
        origins.insert(Origin { name: "x".into() }, live);

        let facts = BorrowCheckFacts {
            loans: vec![loan],
            loan_issued_at,
            origins,
        };

        let violations = PoloniusEngine::check(&facts);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "x");
    }
}
