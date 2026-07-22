//! Inbound adapter: Elixir → neutral AST via tree-sitter.
//! tree-sitter types never escape this crate.
//!
//! Elixir has no dedicated grammar rules for `def`/`defmodule`, or even for
//! control flow (`if`/`case`/`cond`/`for`/`with`/`try` are ordinary macro
//! calls at the syntax level) — everything is a `call` node. This adapter
//! recovers function and module boundaries by inspecting the call target,
//! since those drive `NodeKind::FunctionDef` detection that the rest of the
//! engine (complexity rules, rule `check`s that scan for functions) depends
//! on. Control-flow macros are left as plain `NodeKind::Call` for now — the
//! complexity rules will under-count Elixir branching until those get their
//! own distinguishing treatment, tracked as a follow-up.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{AstParser, ParseError};

pub struct ElixirParser;

impl ElixirParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ElixirParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for ElixirParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::elixir()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_elixir::LANGUAGE.into())
            .map_err(|e| ParseError::Backend(e.to_string()))?;
        let tree = parser.parse(file.content(), None).ok_or_else(|| ParseError::Syntax {
            file: file.path().to_string(),
            detail: "tree-sitter produced no tree".to_string(),
        })?;
        Ok(convert(tree.root_node(), &file.content_shared()))
    }

    fn tokenize_for_duplication(&self, file: &SourceFile) -> Vec<(u32, String)> {
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&tree_sitter_elixir::LANGUAGE.into()).is_err() {
            return yunq_cpd::fallback_tokenize(file);
        }
        let Some(tree) = parser.parse(file.content(), None) else {
            return yunq_cpd::fallback_tokenize(file);
        };
        yunq_treesitter_tokens::statement_lines(&tree, file.content())
    }
}

fn convert(node: tree_sitter::Node<'_>, source: &std::sync::Arc<str>) -> AstNode {
    let mut cursor = node.walk();
    let children = node.named_children(&mut cursor).map(|c| convert(c, source)).collect();
    AstNode::from_source(
        map_kind(node, source),
        span_of(node),
        std::sync::Arc::clone(source),
        node.byte_range(),
        children,
    )
}

fn span_of(node: tree_sitter::Node<'_>) -> Span {
    let (start, end) = (node.start_position(), node.end_position());
    Span::new(start.row as u32 + 1, start.column as u32 + 1, end.row as u32 + 1, end.column as u32 + 1)
}

/// Macro names that define a function-like construct: `def foo(...) do ... end`.
const DEF_MACROS: &[&str] =
    &["def", "defp", "defmacro", "defmacrop", "defguard", "defguardp", "defdelegate"];

/// Macro names that define a module-like namespace.
const MODULE_MACROS: &[&str] = &["defmodule", "defprotocol", "defimpl"];

/// The macro-call target's identifier text, e.g. `"def"` in `def foo, do: 1`
/// — `None` unless `node` is a `call` whose first argument is a bare
/// identifier (true for every special-form-like macro call).
fn call_target<'a>(node: tree_sitter::Node<'_>, source: &'a str) -> Option<&'a str> {
    if node.kind() != "call" {
        return None;
    }
    let mut cursor = node.walk();
    let first = node.named_children(&mut cursor).next()?;
    (first.kind() == "identifier").then(|| &source[first.byte_range()])
}

/// True when `node` is a `binary_operator` whose operator token — recovered
/// from the source gap between its two operands, since tree-sitter's
/// `named_children` drops anonymous tokens like `=` — is exactly `=`.
/// Elixir uses `=` for both pattern-match binding and reassignment; there is
/// no separate variable-declaration grammar rule to key off of instead.
fn is_match_operator(node: tree_sitter::Node<'_>, source: &str) -> bool {
    if node.kind() != "binary_operator" {
        return false;
    }
    let mut cursor = node.walk();
    let named: Vec<_> = node.named_children(&mut cursor).collect();
    let [left, right] = named.as_slice() else { return false };
    source.get(left.end_byte()..right.start_byte()).map(|gap| gap.trim() == "=").unwrap_or(false)
}

fn map_kind(node: tree_sitter::Node<'_>, source: &str) -> NodeKind {
    if let Some(target) = call_target(node, source) {
        if DEF_MACROS.contains(&target) {
            return NodeKind::FunctionDef;
        }
        if MODULE_MACROS.contains(&target) {
            return NodeKind::Other("defmodule".to_string());
        }
    }
    if is_match_operator(node, source) {
        return NodeKind::Assignment;
    }
    match node.kind() {
        "source" => NodeKind::SourceUnit,
        "call" => NodeKind::Call,
        "anonymous_function" => NodeKind::FunctionDef,
        "string" | "charlist" => NodeKind::StringLiteral,
        "identifier" => NodeKind::Identifier,
        "dot" => NodeKind::MemberAccess,
        "comment" => NodeKind::Comment,
        other => NodeKind::Other(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("test.ex", code, LanguageIdentifier::elixir()).unwrap();
        ElixirParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_core_concepts() {
        let ast = parse(
            "defmodule Hello do\n  # TODO: refactor\n  def main do\n    password = \"hunter2\"\n    IO.puts(password)\n  end\nend\n",
        );
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert!(!ast.find_all(&NodeKind::Assignment).is_empty());
        assert!(!ast.find_all(&NodeKind::StringLiteral).is_empty());
    }

    #[test]
    fn io_puts_is_a_call() {
        let ast = parse("IO.puts(\"hi\")\n");
        let calls = ast.find_all(&NodeKind::Call);
        assert!(calls.iter().any(|c| c.text().starts_with("IO.puts")));
    }
}
