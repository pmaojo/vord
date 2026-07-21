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
        Self { start_line, start_col, end_line, end_col }
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
    Other(String),
}

/// A node of the language-neutral AST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AstNode {
    kind: NodeKind,
    span: Span,
    text: String,
    children: Vec<AstNode>,
}

impl AstNode {
    pub fn new(kind: NodeKind, span: Span, text: impl Into<String>, children: Vec<AstNode>) -> Self {
        Self { kind, span, text: text.into(), children }
    }

    pub fn kind(&self) -> &NodeKind {
        &self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }

    /// The exact source text this node covers.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn children(&self) -> &[AstNode] {
        &self.children
    }

    pub fn first_child(&self) -> Option<&AstNode> {
        self.children.first()
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
        self.text.contains(needle)
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
                    vec![leaf(NodeKind::Identifier, "eval"), leaf(NodeKind::Identifier, "x")],
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
    fn span_line_count() {
        assert_eq!(Span::new(2, 1, 5, 3).line_count(), 4);
        assert_eq!(Span::new(7, 1, 7, 9).line_count(), 1);
    }
}
