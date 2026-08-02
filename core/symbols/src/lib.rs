//! Same-file (and, via [`classes::ClassRegistry::build_cross_file`],
//! cross-file) symbol/type resolution over the neutral AST
//! (`vord_ast::AstNode`). This is a *lint-support* symbol table, not a
//! type-checker: it answers narrow questions rules actually need —
//! "is this identifier locally bound or captured from an outer scope",
//! "what's this variable/parameter/field's declared type", and "which
//! class does that type name refer to" — without attempting full
//! type inference, generics, overload resolution, or anything a real
//! compiler's resolver would need.
//!
//! Pure: no I/O, no framework dependencies, `vord-ast` only.

pub mod classes;
pub mod pointer_analysis;
pub mod scope;
pub mod scope_tree;
pub mod types;

pub use classes::{
    ClassInfo, ClassRegistry, MemberInfo, MethodInfo, function_params, is_constructor_name,
};
pub use pointer_analysis::{AndersenAnalysis, PointerConstraint, SteensgaardAnalysis};
pub use scope::{free_identifiers, own_bindings};
pub use scope_tree::{BindingInfo, BindingResolution, Scope, ScopeKind, ScopeTree};
pub use types::{declared_type, is_primitive_type, mentions_collaborator, type_identifiers};
