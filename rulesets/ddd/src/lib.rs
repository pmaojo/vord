//! Domain-Driven Design tactical patterns, enforced.
//!
//! Where `rulesets/architecture` checks the *shape* of the hexagon (which ring
//! may depend on which, what may reach a framework), this ruleset checks the
//! thing inside it: whether the model is a model. An anemic entity, a public
//! setter, a signature of bare strings, an ORM annotation on an aggregate, a
//! collection handed out by reference — each is a way for the domain layer to
//! keep its directory name while losing the property that made it worth having.
//!
//! Every rule here is scoped to the domain layer
//! (`yunq_import_graph::layer_of`, via `common::is_domain_path`), and that scope
//! is load-bearing rather than an optimization. The same shapes are *correct*
//! outside the model: a DTO at an HTTP boundary should be anemic and full of
//! setters, a row type should carry the ORM mapping, a query object should take
//! four strings. Reporting them everywhere would be reporting noise; reporting
//! them on an aggregate root is reporting a design defect.

mod aggregate_reference;
mod anemic_domain_model;
mod common;
mod entity_setter;
mod exposed_collection;
mod persistence_in_domain;
mod primitive_obsession;
mod value_object_mutation;

pub use aggregate_reference::AggregateReferenceByIdRule;
pub use anemic_domain_model::AnemicDomainModelRule;
pub use entity_setter::PublicEntitySetterRule;
pub use exposed_collection::ExposedCollectionRule;
pub use persistence_in_domain::PersistenceInDomainRule;
pub use primitive_obsession::PrimitiveObsessionRule;
pub use value_object_mutation::ValueObjectMutationRule;

use yunq_rules_engine::{CrossFileRule, Rule};

/// Every per-file rule in this ruleset, for composition roots.
pub fn all_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(PersistenceInDomainRule::new())]
}

/// Every whole-program rule in this ruleset, for composition roots. These need
/// the whole file set because a type's methods (Rust `impl` blocks) and its
/// declaration are routinely in different files — the case
/// `ClassRegistry::build_cross_file` exists for.
pub fn all_cross_rules() -> Vec<Box<dyn CrossFileRule>> {
    vec![
        Box::new(AnemicDomainModelRule::default()),
        Box::new(PublicEntitySetterRule::new()),
        Box::new(PrimitiveObsessionRule::default()),
        Box::new(ExposedCollectionRule::new()),
        Box::new(ValueObjectMutationRule::new()),
        Box::new(AggregateReferenceByIdRule::new()),
    ]
}
