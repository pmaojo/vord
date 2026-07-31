//! Language-neutral source model: validated identifiers, source files and a
//! neutral AST that every parser adapter translates into. This crate is pure
//! domain — no I/O, no async, no serialization.

mod edit_distance;
mod gumtree;
mod interner;
mod language;
mod node;
mod pattern;
mod source;

pub use edit_distance::TreeEditDistance;
pub use gumtree::{EditAction, EditScript, GumTreeDiff};
pub use interner::intern;
pub use language::{LanguageIdentifier, UnsupportedLanguageError};
pub use node::{AstNode, Descendants, NodeKind, Span, lookup_kind};
pub use pattern::{MatchResult, Pattern, PatternNode, PatternParseError, Predicate};
pub use source::{SourceFile, SourceFileError};
