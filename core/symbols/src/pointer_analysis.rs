//! Pointer and Alias Analysis Algorithms.
//! - Andersen's Inclusion-Based Pointer Analysis ($O(n^3)$ subset constraint graph solver).
//! - Steensgaard's Unification-Based Pointer Analysis ($O(n \cdot \alpha(n))$ Union-Find equivalence relation).

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum PointerConstraint {
    /// Allocation: ptr = &loc
    AddressOf { ptr: String, loc: String },
    /// Assignment: ptr1 = ptr2 (ptr2 <= ptr1)
    Copy { from: String, to: String },
    /// Dereference Load: ptr1 = *ptr2
    Load { from_ptr: String, to: String },
    /// Dereference Store: *ptr1 = ptr2
    Store { from: String, to_ptr: String },
}

/// Andersen's Inclusion-Based Pointer Analysis ($O(n^3)$ constraint graph solver).
pub struct AndersenAnalysis;

impl AndersenAnalysis {
    /// Solves points-to sets for variables given inclusion constraints.
    pub fn solve(constraints: &[PointerConstraint]) -> HashMap<String, HashSet<String>> {
        let mut pts: HashMap<String, HashSet<String>> = HashMap::new();
        let mut graph: HashMap<String, HashSet<String>> = HashMap::new();

        // Initial pass for AddressOf and Copy constraints
        for c in constraints {
            match c {
                PointerConstraint::AddressOf { ptr, loc } => {
                    pts.entry(ptr.clone()).or_default().insert(loc.clone());
                }
                PointerConstraint::Copy { from, to } => {
                    graph.entry(from.clone()).or_default().insert(to.clone());
                }
                _ => {}
            }
        }

        // Worklist fixed-point transitive closure algorithm
        let mut changed = true;
        while changed {
            changed = false;

            for c in constraints {
                match c {
                    PointerConstraint::Load { from_ptr, to } => {
                        if let Some(locs) = pts.get(from_ptr).cloned() {
                            for loc in locs {
                                if graph.entry(loc.clone()).or_default().insert(to.clone()) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    PointerConstraint::Store { from, to_ptr } => {
                        if let Some(locs) = pts.get(to_ptr).cloned() {
                            for loc in locs {
                                if graph.entry(from.clone()).or_default().insert(loc.clone()) {
                                    changed = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Propagate points-to sets along constraint graph edges
            let nodes: Vec<String> = graph.keys().cloned().collect();
            for from in nodes {
                if let Some(from_pts) = pts.get(&from).cloned() {
                    if let Some(targets) = graph.get(&from).cloned() {
                        for to in targets {
                            let to_pts = pts.entry(to).or_default();
                            let orig_len = to_pts.len();
                            to_pts.extend(from_pts.iter().cloned());
                            if to_pts.len() > orig_len {
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        pts
    }
}

/// Steensgaard's Unification-Based Pointer Analysis ($O(n \cdot \alpha(n))$ Union-Find).
pub struct SteensgaardAnalysis;

impl SteensgaardAnalysis {
    /// Computes points-to equivalence classes using Union-Find.
    pub fn solve(constraints: &[PointerConstraint]) -> HashMap<String, String> {
        let mut uf = UnionFind::new();

        for c in constraints {
            match c {
                PointerConstraint::AddressOf { ptr, loc } => {
                    uf.union(ptr, loc);
                }
                PointerConstraint::Copy { from, to } => {
                    uf.union(from, to);
                }
                PointerConstraint::Load { from_ptr, to } => {
                    uf.union(from_ptr, to);
                }
                PointerConstraint::Store { from, to_ptr } => {
                    uf.union(from, to_ptr);
                }
            }
        }

        let mut vars = HashSet::new();
        for c in constraints {
            match c {
                PointerConstraint::AddressOf { ptr, loc } => {
                    vars.insert(ptr.clone());
                    vars.insert(loc.clone());
                }
                PointerConstraint::Copy { from, to } => {
                    vars.insert(from.clone());
                    vars.insert(to.clone());
                }
                PointerConstraint::Load { from_ptr, to } => {
                    vars.insert(from_ptr.clone());
                    vars.insert(to.clone());
                }
                PointerConstraint::Store { from, to_ptr } => {
                    vars.insert(from.clone());
                    vars.insert(to_ptr.clone());
                }
            }
        }

        let mut res = HashMap::new();
        for var in vars {
            let root = uf.find(&var);
            res.insert(var, root);
        }

        res
    }
}

struct UnionFind {
    parent: HashMap<String, String>,
}

impl UnionFind {
    fn new() -> Self {
        UnionFind {
            parent: HashMap::new(),
        }
    }

    fn find(&mut self, item: &str) -> String {
        let p = match self.parent.get(item) {
            Some(parent) => parent.clone(),
            None => {
                self.parent.insert(item.to_string(), item.to_string());
                return item.to_string();
            }
        };
        if p == item {
            item.to_string()
        } else {
            let root = self.find(&p);
            self.parent.insert(item.to_string(), root.clone());
            root
        }
    }

    fn union(&mut self, x: &str, y: &str) {
        let root_x = self.find(x);
        let root_y = self.find(y);
        if root_x != root_y {
            self.parent.insert(root_x, root_y);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn andersen_solves_points_to_sets() {
        let constraints = vec![
            PointerConstraint::AddressOf {
                ptr: "p".into(),
                loc: "a".into(),
            },
            PointerConstraint::Copy {
                from: "p".into(),
                to: "q".into(),
            },
        ];

        let pts = AndersenAnalysis::solve(&constraints);
        assert!(pts.get("p").unwrap().contains("a"));
        assert!(pts.get("q").unwrap().contains("a"));
    }

    #[test]
    fn steensgaard_unifies_equivalence_classes() {
        let constraints = vec![
            PointerConstraint::AddressOf {
                ptr: "p".into(),
                loc: "a".into(),
            },
            PointerConstraint::Copy {
                from: "p".into(),
                to: "q".into(),
            },
        ];

        let eq = SteensgaardAnalysis::solve(&constraints);
        assert_eq!(eq.get("p"), eq.get("q"));
    }
}
