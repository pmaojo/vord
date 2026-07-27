//! Portfolios: hierarchical aggregation across projects with rollup ratings.
//!
//! ROADMAP §Phase 7 — executive-level views across projects, applications
//! and portfolios (health overview, risk distribution, trends).
//!
//! Skeleton: the type + tree-walk API is in place; the persistence and HTTP
//! surface land in following iterations. The aggregator is pure so it can
//! be unit-tested without a database.

use serde::{Deserialize, Serialize};

/// One node in the portfolio tree — either a leaf project or a sub-portfolio.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortfolioNode {
    pub id: String,
    pub name: String,
    pub children: Vec<PortfolioNode>,
}

/// Aggregated health/quality roll-up over a portfolio subtree. The ratings
/// are SonarQube's `1.0`–`5.0` encoding (A..E); the worst wins for the
/// reliability/security/maintainability rating per node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortfolioRollup {
    pub node_id: String,
    pub reliability_rating: f32,
    pub security_rating: f32,
    pub maintainability_rating: f32,
    pub project_count: usize,
    pub bug_total: i64,
    pub vulnerability_total: i64,
    pub code_smell_total: i64,
}

/// One project's leaf input to a rollup.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectRollupInput {
    pub project_id: String,
    pub reliability_rating: f32,
    pub security_rating: f32,
    pub maintainability_rating: f32,
    pub bug_total: i64,
    pub vulnerability_total: i64,
    pub code_smell_total: i64,
}

impl PortfolioRollup {
    /// Flatten a tree of project leaves into a flat list (depth-first).
    pub fn flatten_projects(node: &PortfolioNode) -> Vec<&PortfolioNode> {
        let mut out = Vec::new();
        fn walk<'a>(n: &'a PortfolioNode, out: &mut Vec<&'a PortfolioNode>) {
            out.push(n);
            for c in &n.children {
                walk(c, out);
            }
        }
        walk(node, &mut out);
        out
    }

    /// Take the worst (max) rating across `inputs` for each dimension.
    pub fn worst_of(inputs: &[ProjectRollupInput]) -> PortfolioRollup {
        let mut r = PortfolioRollup {
            node_id: "aggregate".to_string(),
            reliability_rating: 1.0,
            security_rating: 1.0,
            maintainability_rating: 1.0,
            project_count: inputs.len(),
            bug_total: 0,
            vulnerability_total: 0,
            code_smell_total: 0,
        };
        for i in inputs {
            r.reliability_rating = r.reliability_rating.max(i.reliability_rating);
            r.security_rating = r.security_rating.max(i.security_rating);
            r.maintainability_rating = r.maintainability_rating.max(i.maintainability_rating);
            r.bug_total += i.bug_total;
            r.vulnerability_total += i.vulnerability_total;
            r.code_smell_total += i.code_smell_total;
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(id: &str, _rel: f32, _sec: f32, _maint: f32) -> PortfolioNode {
        PortfolioNode {
            id: id.to_string(),
            name: id.to_string(),
            children: vec![],
        }
    }

    fn project_input(
        id: &str,
        rel: f32,
        sec: f32,
        maint: f32,
        bugs: i64,
        vulns: i64,
        smells: i64,
    ) -> ProjectRollupInput {
        ProjectRollupInput {
            project_id: id.to_string(),
            reliability_rating: rel,
            security_rating: sec,
            maintainability_rating: maint,
            bug_total: bugs,
            vulnerability_total: vulns,
            code_smell_total: smells,
        }
    }

    #[test]
    fn flatten_returns_leaves_depth_first() {
        let tree = PortfolioNode {
            id: "root".to_string(),
            name: "root".to_string(),
            children: vec![
                leaf("a", 1.0, 1.0, 1.0),
                PortfolioNode {
                    id: "sub".to_string(),
                    name: "sub".to_string(),
                    children: vec![leaf("b", 2.0, 2.0, 2.0), leaf("c", 3.0, 3.0, 3.0)],
                },
            ],
        };
        let ids: Vec<_> = PortfolioRollup::flatten_projects(&tree)
            .into_iter()
            .map(|n| n.id.clone())
            .collect();
        assert_eq!(ids, vec!["root", "a", "sub", "b", "c"]);
    }

    #[test]
    fn worst_of_picks_the_worst_rating_per_dimension() {
        let inputs = vec![
            project_input("a", 2.0, 3.0, 1.0, 1, 1, 1),
            project_input("b", 4.0, 1.0, 3.0, 2, 2, 2),
            project_input("c", 1.0, 5.0, 2.0, 3, 3, 3),
        ];
        let r = PortfolioRollup::worst_of(&inputs);
        assert_eq!(r.reliability_rating, 4.0);
        assert_eq!(r.security_rating, 5.0);
        assert_eq!(r.maintainability_rating, 3.0);
        assert_eq!(r.bug_total, 6);
        assert_eq!(r.vulnerability_total, 6);
        assert_eq!(r.code_smell_total, 6);
        assert_eq!(r.project_count, 3);
    }

    #[test]
    fn worst_of_empty_inputs_returns_defaults() {
        let r = PortfolioRollup::worst_of(&[]);
        assert_eq!(r.project_count, 0);
        assert_eq!(r.bug_total, 0);
        assert_eq!(r.reliability_rating, 1.0); // default floor
    }
}
