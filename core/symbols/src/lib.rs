//! Same-file (and, via [`classes::ClassRegistry::build_cross_file`],
//! cross-file) symbol/type resolution over the neutral AST
//! (`yunq_ast::AstNode`). This is a *lint-support* symbol table, not a
//! type-checker: it answers narrow questions rules actually need —
//! "is this identifier locally bound or captured from an outer scope",
//! "what's this variable/parameter/field's declared type", and "which
//! class does that type name refer to" — without attempting full
//! type inference, generics, overload resolution, or anything a real
//! compiler's resolver would need.
//!
//! Pure: no I/O, no framework dependencies, `yunq-ast` only.

pub mod classes;
pub mod scope;
pub mod types;

pub use classes::{function_params, is_constructor_name, ClassInfo, ClassRegistry, MemberInfo, MethodInfo};
pub use scope::{free_identifiers, own_bindings};
pub use types::{declared_type, is_primitive_type, mentions_collaborator};
