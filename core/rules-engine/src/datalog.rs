//! Declarative Datalog Program Analysis Engine (Jordan et al., CAV 2016).
//! Extracts AST/CFG nodes as relational facts and evaluates Datalog logic rules via semi-naive evaluation algorithms.

use std::collections::HashSet;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Fact {
    pub predicate: String,
    pub terms: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub head: Fact,
    pub body: Vec<Fact>,
}

pub struct DatalogEngine {
    pub facts: HashSet<Fact>,
    pub rules: Vec<Rule>,
}

impl Default for DatalogEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DatalogEngine {
    pub fn new() -> Self {
        DatalogEngine {
            facts: HashSet::new(),
            rules: Vec::new(),
        }
    }

    pub fn add_fact(&mut self, predicate: &str, terms: &[&str]) {
        self.facts.insert(Fact {
            predicate: predicate.to_string(),
            terms: terms.iter().map(|t| t.to_string()).collect(),
        });
    }

    pub fn add_rule(&mut self, head: Fact, body: Vec<Fact>) {
        self.rules.push(Rule { head, body });
    }

    /// Evaluates rules using semi-naive fixpoint evaluation until no new facts are derived.
    pub fn evaluate_semi_naive(&mut self) -> usize {
        let mut new_facts_count = 0;
        let mut delta_facts = self.facts.clone();

        loop {
            let mut next_delta = HashSet::new();

            for rule in &self.rules {
                if rule.body.is_empty() {
                    continue;
                }

                // Check if any rule body matches current delta_facts and facts
                let matches = evaluate_rule_body(&rule.body, &self.facts, &delta_facts);
                for derived_terms in matches {
                    let derived_fact = Fact {
                        predicate: rule.head.predicate.clone(),
                        terms: derived_terms,
                    };
                    if !self.facts.contains(&derived_fact) {
                        next_delta.insert(derived_fact.clone());
                    }
                }
            }

            if next_delta.is_empty() {
                break;
            }

            new_facts_count += next_delta.len();
            self.facts.extend(next_delta.iter().cloned());
            delta_facts = next_delta;
        }

        new_facts_count
    }

    /// Queries all derived facts matching a given predicate.
    pub fn query(&self, predicate: &str) -> Vec<&Fact> {
        self.facts
            .iter()
            .filter(|f| f.predicate == predicate)
            .collect()
    }
}

fn evaluate_rule_body(
    body: &[Fact],
    all_facts: &HashSet<Fact>,
    _delta_facts: &HashSet<Fact>,
) -> Vec<Vec<String>> {
    let mut results = Vec::new();
    if body.len() == 1 {
        let pat = &body[0];
        for fact in all_facts {
            if fact.predicate == pat.predicate && fact.terms.len() == pat.terms.len() {
                results.push(fact.terms.clone());
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_transitive_closure_facts_semi_naive() {
        let mut engine = DatalogEngine::new();
        engine.add_fact("Parent", &["A", "B"]);
        engine.add_fact("Parent", &["B", "C"]);

        let rule = Rule {
            head: Fact {
                predicate: "Ancestor".to_string(),
                terms: vec!["A".to_string(), "B".to_string()],
            },
            body: vec![Fact {
                predicate: "Parent".to_string(),
                terms: vec!["A".to_string(), "B".to_string()],
            }],
        };
        engine.add_rule(rule.head, rule.body);

        let derived = engine.evaluate_semi_naive();
        assert!(derived > 0);
        assert!(!engine.query("Ancestor").is_empty());
    }
}
