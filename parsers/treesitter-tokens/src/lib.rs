//! Grammar-agnostic leaf tokenizer shared by every `parsers/treesitter-*`
//! adapter, used to feed copy-paste detection (`core/duplication`) real
//! per-language tokens instead of trimmed source lines.
//!
//! Walks a parsed tree-sitter tree left to right over *all* children
//! (named and anonymous — punctuation and operators included, unlike the
//! neutral-AST `convert` step each parser also has, which keeps only named
//! children for rule structural contracts). Two normalizations happen along
//! the way:
//!
//! - Any node whose grammar kind name looks like a string/char/template or
//!   numeric literal (a name-based heuristic — tree-sitter grammars name
//!   these consistently, e.g. `string_literal`, `integer_literal`,
//!   `template_string`) is collapsed to one placeholder token and its
//!   subtree is not descended into. This is what makes `x = 1;` and
//!   `x = 2;` hash as the same statement instead of differing on literal
//!   text.
//! - Any node whose kind name contains "comment" is dropped entirely, so
//!   comment-only lines never register as duplicated statements.
//!
//! Tokens are then grouped by the source line they start on and joined with
//! a single space, so intra-line whitespace differences (`x=1` vs `x = 1`)
//! stop affecting the hash — only leading/trailing whitespace mattered
//! before this, via `str::trim`.

pub use yunq_cpd::{TokenNormalization, IDENTIFIER_PLACEHOLDER};

const STRING_PLACEHOLDER: &str = "\u{0}STR\u{0}";
const NUMBER_PLACEHOLDER: &str = "\u{0}NUM\u{0}";

/// Per-line, whitespace- and literal-normalized token text for one parsed
/// file. `line_number` is 1-based; lines with no significant tokens (blank
/// or comment-only) are omitted.
pub fn statement_lines(tree: &tree_sitter::Tree, source: &str) -> Vec<(u32, String)> {
    statement_lines_with(tree, source, TokenNormalization::default())
}

/// [`statement_lines`] with an explicit normalization policy — see
/// [`TokenNormalization`] for what erasing identifiers buys and costs.
pub fn statement_lines_with(
    tree: &tree_sitter::Tree,
    source: &str,
    normalization: TokenNormalization,
) -> Vec<(u32, String)> {
    let mut tokens: Vec<(u32, &str)> = Vec::new();
    walk(tree.root_node(), source.as_bytes(), normalization, &mut tokens);

    let mut grouped: Vec<(u32, String)> = Vec::new();
    for (line, token) in tokens {
        match grouped.last_mut() {
            Some((last_line, text)) if *last_line == line => {
                text.push(' ');
                text.push_str(token);
            }
            _ => grouped.push((line, token.to_string())),
        }
    }
    grouped
}

fn walk<'a>(
    node: tree_sitter::Node<'a>,
    source: &'a [u8],
    normalization: TokenNormalization,
    out: &mut Vec<(u32, &'a str)>,
) {
    let kind = node.kind();
    if is_comment(kind) {
        return;
    }
    if let Some(placeholder) = literal_placeholder(kind) {
        out.push((node.start_position().row as u32 + 1, placeholder));
        return;
    }
    // Every grammar names its name-carrying leaves `*identifier`
    // (`identifier`, `type_identifier`, `field_identifier`,
    // `property_identifier`, ...), which is what makes this one rule work
    // across languages instead of needing a per-grammar list. Keywords and
    // punctuation are anonymous nodes and keep their text, so the block's
    // structure still has to match.
    if normalization.identifiers && is_identifier(kind) && node.child_count() == 0 {
        out.push((node.start_position().row as u32 + 1, IDENTIFIER_PLACEHOLDER));
        return;
    }
    if node.child_count() == 0 {
        let text = node.utf8_text(source).unwrap_or("");
        if !text.trim().is_empty() {
            out.push((node.start_position().row as u32 + 1, text));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, source, normalization, out);
    }
}

fn is_identifier(kind: &str) -> bool {
    kind.ends_with("identifier")
}

fn is_comment(kind: &str) -> bool {
    kind.to_ascii_lowercase().contains("comment")
}

fn literal_placeholder(kind: &str) -> Option<&'static str> {
    let k = kind.to_ascii_lowercase();
    let is_string = k.contains("string")
        || k.contains("char_literal")
        || k == "char"
        || k.contains("template_string")
        || k.contains("rune_literal")
        || k.contains("heredoc");
    if is_string {
        return Some(STRING_PLACEHOLDER);
    }
    let is_number = k.contains("integer")
        || k.contains("float")
        || k.contains("number")
        || k.contains("numeric")
        || k.contains("decimal")
        || k.contains("octal")
        || k.contains("hex_literal")
        || k == "int_literal";
    if is_number {
        return Some(NUMBER_PLACEHOLDER);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(lang: tree_sitter::Language, source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();
        parser.parse(source, None).unwrap()
    }

    #[test]
    fn normalizes_literal_values_so_differing_literals_match() {
        let a = parse(tree_sitter_python::LANGUAGE.into(), "x = 1\n");
        let b = parse(tree_sitter_python::LANGUAGE.into(), "x = 2\n");
        let lines_a = statement_lines(&a, "x = 1\n");
        let lines_b = statement_lines(&b, "x = 2\n");
        assert_eq!(lines_a.len(), 1);
        assert_eq!(lines_a[0].1, lines_b[0].1);
    }

    #[test]
    fn normalizes_internal_whitespace() {
        let src_tight = "x=1\n";
        let src_wide = "x   =   1\n";
        let a = parse(tree_sitter_python::LANGUAGE.into(), src_tight);
        let b = parse(tree_sitter_python::LANGUAGE.into(), src_wide);
        let lines_a = statement_lines(&a, src_tight);
        let lines_b = statement_lines(&b, src_wide);
        assert_eq!(lines_a[0].1, lines_b[0].1);
    }

    #[test]
    fn drops_comment_only_lines() {
        let src = "# just a comment\nx = 1\n";
        let tree = parse(tree_sitter_python::LANGUAGE.into(), src);
        let lines = statement_lines(&tree, src);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, 2);
    }

    #[test]
    fn distinct_identifiers_still_differ() {
        let src_a = "x = 1\n";
        let src_b = "y = 1\n";
        let a = parse(tree_sitter_python::LANGUAGE.into(), src_a);
        let b = parse(tree_sitter_python::LANGUAGE.into(), src_b);
        let lines_a = statement_lines(&a, src_a);
        let lines_b = statement_lines(&b, src_b);
        assert_ne!(lines_a[0].1, lines_b[0].1);
    }
}
