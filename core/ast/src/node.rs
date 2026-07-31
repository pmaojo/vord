use std::fmt;
use std::sync::Arc;

/// A half-open source region. Lines and columns are 1-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl Span {
    pub fn new(start_line: u32, start_col: u32, end_line: u32, end_col: u32) -> Self {
        Self {
            start_line,
            start_col,
            end_line,
            end_col,
        }
    }

    pub fn line_count(&self) -> u32 {
        self.end_line.saturating_sub(self.start_line) + 1
    }
}

/// The closed vocabulary of node concepts rules reason about. Parser adapters
/// map their concrete grammars onto these; anything without a neutral meaning
/// is preserved as `Other` so no information is silently dropped.
///
/// Structural contracts parsers must uphold:
/// - `VariableDecl`: first child is the declared `Identifier`, remaining
///   children form the initializer expression.
/// - `Assignment`: first child is the target, remaining children the value.
/// - `Call`: first child is the callee (`Identifier` or `MemberAccess`),
///   remaining children are the arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeKind {
    SourceUnit,
    FunctionDef,
    Call,
    StringLiteral,
    Identifier,
    Assignment,
    VariableDecl,
    MemberAccess,
    Comment,
    /// A grammar node kind with no neutral meaning, preserved verbatim as
    /// the raw tree-sitter kind name (e.g. `"if_statement"`). Interned
    /// (`crate::intern`) rather than freshly allocated: the same handful of
    /// kind strings per grammar recur on a huge share of a file's nodes.
    Other(Arc<str>),
}

/// Shared table-lookup helper for parser `map_kind` functions: an
/// `.iter().find()` over a `(tree-sitter kind, NodeKind)` table has
/// cyclomatic complexity 1 regardless of table size, unlike the long
/// `match` statement it replaces (McCabe counts every arm as a branch).
/// Unmapped kinds fall back to `NodeKind::Other`.
pub fn lookup_kind(table: &[(&str, NodeKind)], kind: &str) -> NodeKind {
    table
        .iter()
        .find(|(ts_kind, _)| *ts_kind == kind)
        .map(|(_, node_kind)| node_kind.clone())
        .unwrap_or_else(|| NodeKind::Other(crate::intern(kind)))
}

/// A node of the language-neutral AST.
///
/// Zero-copy by construction: every node in a parsed tree shares one
/// `Arc<str>` source buffer and holds only a byte range into it, so building
/// an AST allocates no per-node text. Hand-built nodes (tests, synthetic
/// trees) own a private buffer via [`AstNode::new`].
#[derive(Clone)]
pub struct AstNode {
    kind: NodeKind,
    span: Span,
    source: Arc<str>,
    start: u32,
    end: u32,
    children: Vec<AstNode>,
}

impl AstNode {
    /// A node owning its own text. Intended for hand-built trees; parsers
    /// should use [`AstNode::from_source`] to share one buffer per file.
    pub fn new(
        kind: NodeKind,
        span: Span,
        text: impl Into<String>,
        children: Vec<AstNode>,
    ) -> Self {
        let source: Arc<str> = text.into().into();
        let end = source.len() as u32;
        Self {
            kind,
            span,
            source,
            start: 0,
            end,
            children,
        }
    }

    /// A zero-copy node covering `range` bytes of a shared source buffer.
    pub fn from_source(
        kind: NodeKind,
        span: Span,
        source: Arc<str>,
        range: std::ops::Range<usize>,
        children: Vec<AstNode>,
    ) -> Self {
        debug_assert!(
            source.get(range.clone()).is_some(),
            "range must lie on char boundaries"
        );
        Self {
            kind,
            span,
            source,
            start: range.start as u32,
            end: range.end as u32,
            children,
        }
    }

    pub fn kind(&self) -> &NodeKind {
        &self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    /// The exact source text this node covers (a borrowed slice — no copy).
    pub fn text(&self) -> &str {
        self.source
            .get(self.start as usize..self.end as usize)
            .unwrap_or("")
    }

    pub fn children(&self) -> &[AstNode] {
        &self.children
    }

    /// The byte range this node covers in its shared source buffer. Lets
    /// callers slice the gap between two of a node's own children (e.g. an
    /// anonymous operator token tree-sitter drops from `named_children`)
    /// without re-deriving offsets from `Span`'s line/column coordinates.
    pub fn byte_range(&self) -> std::ops::Range<usize> {
        self.start as usize..self.end as usize
    }

    pub fn first_child(&self) -> Option<&AstNode> {
        self.children.first()
    }

    /// The source text between two of this node's descendants — the operator
    /// token tree-sitter drops from `named_children`.
    ///
    /// Grammars model `a instanceof B`, `x += 1` and `typeof x` with the
    /// operator as an *anonymous* token, so it never becomes an `AstNode`. A
    /// rule that needs to know *which* operator a `binary_expression` or an
    /// `Assignment` uses has exactly two options: match the parent's whole text
    /// with a substring search (which sees operators inside string literals and
    /// comments too), or read the gap between the operands, which is what the
    /// grammar actually says. This is the second one.
    ///
    /// `None` when the two nodes are not in this node's buffer in order, so a
    /// caller cannot accidentally slice an unrelated range.
    pub fn text_between(&self, first: &AstNode, second: &AstNode) -> Option<&str> {
        if first.end > second.start || first.start < self.start || second.end > self.end {
            return None;
        }
        self.source.get(first.end as usize..second.start as usize)
    }

    /// Pre-order traversal of this node and every descendant.
    pub fn descendants(&self) -> Descendants<'_> {
        Descendants { stack: vec![self] }
    }

    pub fn find_all<'a>(&'a self, kind: &NodeKind) -> Vec<&'a AstNode> {
        self.descendants().filter(|n| n.kind() == kind).collect()
    }

    /// Whether any node in this subtree contains `needle` in its text.
    pub fn subtree_contains_text(&self, needle: &str) -> bool {
        self.text().contains(needle)
    }
}

impl PartialEq for AstNode {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.span == other.span
            && self.text() == other.text()
            && self.children == other.children
    }
}

impl Eq for AstNode {}

impl fmt::Debug for AstNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AstNode")
            .field("kind", &self.kind)
            .field("span", &self.span)
            .field("text", &self.text())
            .field("children", &self.children)
            .finish()
    }
}

pub struct Descendants<'a> {
    stack: Vec<&'a AstNode>,
}

impl<'a> Iterator for Descendants<'a> {
    type Item = &'a AstNode;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;
        self.stack.extend(node.children.iter().rev());
        Some(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(kind: NodeKind, text: &str) -> AstNode {
        AstNode::new(kind, Span::new(1, 1, 1, 1), text, vec![])
    }

    #[test]
    fn descendants_is_preorder_and_includes_self() {
        let tree = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 3, 1),
            "root",
            vec![
                AstNode::new(
                    NodeKind::Call,
                    Span::new(1, 1, 1, 10),
                    "eval(x)",
                    vec![
                        leaf(NodeKind::Identifier, "eval"),
                        leaf(NodeKind::Identifier, "x"),
                    ],
                ),
                leaf(NodeKind::Comment, "// done"),
            ],
        );
        let kinds: Vec<_> = tree.descendants().map(|n| n.kind().clone()).collect();
        assert_eq!(
            kinds,
            vec![
                NodeKind::SourceUnit,
                NodeKind::Call,
                NodeKind::Identifier,
                NodeKind::Identifier,
                NodeKind::Comment,
            ]
        );
        assert_eq!(tree.find_all(&NodeKind::Identifier).len(), 2);
    }

    #[test]
    fn shared_buffer_nodes_slice_without_copying() {
        let source: Arc<str> = Arc::from("let x = eval(input);");
        let ident = AstNode::from_source(
            NodeKind::Identifier,
            Span::new(1, 9, 1, 13),
            Arc::clone(&source),
            8..12,
            vec![],
        );
        assert_eq!(ident.text(), "eval");
        // The child borrows the same allocation as the file buffer.
        assert_eq!(Arc::strong_count(&source), 2);
    }

    #[test]
    fn text_between_reads_the_operator_the_grammar_drops() {
        let source: Arc<str> = Arc::from("total += amount");
        let left = AstNode::from_source(
            NodeKind::Identifier,
            Span::new(1, 1, 1, 6),
            Arc::clone(&source),
            0..5,
            vec![],
        );
        let right = AstNode::from_source(
            NodeKind::Identifier,
            Span::new(1, 10, 1, 16),
            Arc::clone(&source),
            9..15,
            vec![],
        );
        let assignment = AstNode::from_source(
            NodeKind::Assignment,
            Span::new(1, 1, 1, 16),
            Arc::clone(&source),
            0..15,
            vec![left.clone(), right.clone()],
        );
        assert_eq!(assignment.text_between(&left, &right), Some(" += "));
    }

    #[test]
    fn text_between_refuses_nodes_out_of_order_or_out_of_range() {
        let source: Arc<str> = Arc::from("a = b");
        let node = |range: std::ops::Range<usize>| {
            AstNode::from_source(
                NodeKind::Identifier,
                Span::new(1, 1, 1, 2),
                Arc::clone(&source),
                range,
                vec![],
            )
        };
        let (left, right) = (node(0..1), node(4..5));
        let parent = AstNode::from_source(
            NodeKind::Assignment,
            Span::new(1, 1, 1, 6),
            Arc::clone(&source),
            0..5,
            vec![left.clone(), right.clone()],
        );
        assert_eq!(parent.text_between(&right, &left), None);
    }

    #[test]
    fn span_line_count() {
        assert_eq!(Span::new(2, 1, 5, 3).line_count(), 4);
        assert_eq!(Span::new(7, 1, 7, 9).line_count(), 1);
    }
}
