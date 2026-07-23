//! Language-neutral source model: validated identifiers, source files and a
//! neutral AST that every parser adapter translates into. This crate is pure
//! domain — no I/O, no async, no serialization.

mod language;
mod node;
mod source;

pub use language::{LanguageIdentifier, UnsupportedLanguageError};
pub use node::{AstNode, Descendants, NodeKind, Span, lookup_kind};
pub use source::{SourceFile, SourceFileError};
