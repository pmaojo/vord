//! The half of a `parsers/treesitter-*` adapter that is the same in every
//! one of them.
//!
//! Each adapter exists to answer two questions — *which tree-sitter
//! grammar* and *how do its node kinds map onto the neutral
//! [`NodeKind`]* — and nothing else. Everything around those two answers
//! (driving the parser, converting the tree, computing spans, falling back
//! when a grammar fails to load) is mechanical and was copied into all 23
//! crates: vord's own duplication detector reported one 26-line block
//! shared by 22 of them, its single largest finding.
//!
//! Copied code is not just redundant, it drifts. The `parse` bodies here
//! had already diverged in three crates for no reason anyone intended, and
//! a fix to the shared shape — the way `tokenize_for_duplication` had to
//! learn about [`TokenNormalization`] — meant editing every copy and
//! hoping none was missed.
//!
//! An adapter now supplies its grammar and its `map_kind` and gets the
//! rest, either piecewise ([`parse_with`]/[`tokenize_with`]) or whole
//! ([`declare_parser!`]).

use std::sync::Arc;

use vord_ast::{AstNode, NodeKind, SourceFile, Span};
use vord_cpd::{TokenNormalization, TokenizedSource};
use vord_rules_engine::ParseError;

/// Maps one grammar's node-kind name onto the neutral AST. The only piece
/// of a conversion that is language-specific.
pub type KindMapper = fn(&str) -> NodeKind;

/// tree-sitter's 0-based row/column as a 1-based [`Span`].
pub fn span_of(node: tree_sitter::Node<'_>) -> Span {
    let (start, end) = (node.start_position(), node.end_position());
    Span::new(
        start.row as u32 + 1,
        start.column as u32 + 1,
        end.row as u32 + 1,
        end.column as u32 + 1,
    )
}

/// Converts a tree-sitter tree into the neutral AST, keeping only *named*
/// children — anonymous punctuation is grammar detail that rules must not
/// depend on. Zero-copy: every node slices the one shared file buffer.
pub fn convert(node: tree_sitter::Node<'_>, source: &Arc<str>, map_kind: KindMapper) -> AstNode {
    let mut cursor = node.walk();
    let children = node
        .named_children(&mut cursor)
        .map(|c| convert(c, source, map_kind))
        .collect();
    AstNode::from_source(
        map_kind(node.kind()),
        span_of(node),
        Arc::clone(source),
        node.byte_range(),
        children,
    )
}

/// Parses `file` with `language` and converts the result. A grammar that
/// fails to load is a [`ParseError::Backend`]; a file tree-sitter declines
/// to parse at all is a [`ParseError::Syntax`].
pub fn parse_with(
    language: &tree_sitter::Language,
    file: &SourceFile,
    map_kind: KindMapper,
) -> Result<AstNode, ParseError> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(language)
        .map_err(|e| ParseError::Backend(e.to_string()))?;
    let tree = parser
        .parse(file.content(), None)
        .ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
    Ok(convert(tree.root_node(), &file.content_shared(), map_kind))
}

/// Per-line normalized tokens for copy-paste detection.
///
/// Degrades to [`vord_cpd::fallback_tokenize`] rather than failing: a
/// grammar that will not load should cost precision, not silently drop the
/// file out of duplication detection entirely.
pub fn tokenize_with(
    language: &tree_sitter::Language,
    file: &SourceFile,
    normalization: TokenNormalization,
) -> TokenizedSource {
    let degraded = || TokenizedSource {
        lines: vord_cpd::fallback_tokenize(file),
        declaration_lines: Vec::new(),
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(language).is_err() {
        return degraded();
    }
    let Some(tree) = parser.parse(file.content(), None) else {
        return degraded();
    };
    vord_treesitter_tokens::tokenize(&tree, file.content(), normalization)
}

/// Declares a whole `AstParser` adapter from the two things that actually
/// differ between them: the grammar and the kind mapping.
///
/// ```ignore
/// declare_parser!(BashParser, LanguageIdentifier::bash(), tree_sitter_bash::LANGUAGE, map_kind);
/// ```
///
/// Expands to the unit struct, its `new`/`Default`, and an `AstParser` impl
/// delegating to [`parse_with`]/[`tokenize_with`].
#[macro_export]
macro_rules! declare_parser {
    ($name:ident, $language_id:expr, $grammar:expr, $map_kind:path) => {
        pub struct $name;

        impl $name {
            pub fn new() -> Self {
                Self
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $crate::__reexport::AstParser for $name {
            fn language(&self) -> $crate::__reexport::LanguageIdentifier {
                $language_id
            }

            fn parse(
                &self,
                file: &$crate::__reexport::SourceFile,
            ) -> ::core::result::Result<$crate::__reexport::AstNode, $crate::__reexport::ParseError>
            {
                $crate::parse_with(&$grammar.into(), file, $map_kind)
            }

            fn tokenize_for_duplication(
                &self,
                file: &$crate::__reexport::SourceFile,
                normalization: $crate::__reexport::TokenNormalization,
            ) -> $crate::__reexport::TokenizedSource {
                $crate::tokenize_with(&$grammar.into(), file, normalization)
            }
        }
    };
}

/// Names [`declare_parser!`] expands to, so a caller needs only this crate
/// in scope rather than the right set of `use` lines.
#[doc(hidden)]
pub mod __reexport {
    pub use vord_ast::{AstNode, LanguageIdentifier, SourceFile};
    pub use vord_cpd::{TokenNormalization, TokenizedSource};
    pub use vord_rules_engine::{AstParser, ParseError};
}
