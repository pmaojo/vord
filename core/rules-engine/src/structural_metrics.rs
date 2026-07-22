//! Structural counters derived from the neutral AST — functions, classes,
//! statements, comment lines, and control-flow nesting depth. Grammar node
//! kinds are matched by their raw tree-sitter name (via `NodeKind::Other`),
//! the same pattern-matching approach already used by
//! `rulesets/code-smells::ComplexityRule` for decision points: no single
//! neutral `NodeKind` variant fits "class" or "statement" across every
//! registered language, so the roster below is grown from the grammars
//! actually vendored in `parsers/treesitter-*`, not guessed.

use yunq_ast::{AstNode, NodeKind};

/// Grammar node kinds that denote a class-like type definition (class,
/// struct, interface, enum, trait...) across the registered language roster.
const CLASS_KINDS: &[&str] = &[
    // class-flavored
    "class_definition",
    "class_declaration",
    "class_specifier",
    "class",
    // struct-flavored
    "struct_item",
    "struct_declaration",
    "struct_specifier",
    "struct_type",
    // interface/protocol-flavored
    "interface_declaration",
    "interface_type",
    "protocol_declaration",
    // trait-flavored
    "trait_item",
    "trait_declaration",
    "trait_definition",
    // enum-flavored
    "enum_item",
    "enum_declaration",
    // misc
    "record_declaration",
    "object_declaration",
    "object_definition",
    "union_specifier",
    "module", // Ruby's `module` keyword; Python's own "module" root is remapped to SourceUnit
    "defmodule", // Elixir's `defmodule`/`defprotocol`/`defimpl`, recovered from a macro call
];

/// Grammar node kinds that denote one executable statement. Declaration
/// wrappers whose only content is a `NodeKind::VariableDecl`/`Assignment`
/// child (e.g. TypeScript's `lexical_declaration`) are deliberately excluded
/// to avoid double-counting that same statement twice.
const STATEMENT_KINDS: &[&str] = &[
    "expression_statement",
    "empty_statement",
    "pass_statement",
    "return_statement",
    "if_statement",
    "for_statement",
    "for_in_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "expression_switch_statement",
    "type_switch_statement",
    "labeled_statement",
    "break_statement",
    "continue_statement",
    "throw_statement",
    "try_statement",
    "yield_statement",
    "assert_statement",
    "goto_statement",
    "using_statement",
    "lock_statement",
    "unsafe_statement",
    "go_statement",
    "defer_statement",
    "send_statement",
    "inc_statement",
    "dec_statement",
    "fallthrough_statement",
    // Rust's control-flow forms are expressions, not statements, but still
    // occupy one statement slot inside a block.
    "if_expression",
    "while_expression",
    "for_expression",
    "loop_expression",
    "match_expression",
    "return_expression",
    "break_expression",
    "continue_expression",
    "enhanced_for_statement", // Groovy/Java-family for-each
    "switch_expression", // Groovy's unified switch statement/expression form
    "repeat_statement", // Lua's `repeat ... until`
];

/// Grammar node kinds that introduce one level of control-flow nesting.
const NESTING_KINDS: &[&str] = &[
    "if_statement",
    "if_expression",
    "for_statement",
    "for_expression",
    "for_in_statement",
    "foreach_statement",
    "while_statement",
    "while_expression",
    "do_statement",
    "loop_expression",
    "switch_statement",
    "expression_switch_statement",
    "type_switch_statement",
    "match_expression",
    "try_statement",
    "catch_clause",
    "enhanced_for_statement", // Groovy/Java-family for-each
    "switch_expression", // Groovy's unified switch statement/expression form
    "repeat_statement", // Lua's `repeat ... until`
];

/// Aggregated structural counters for one parsed file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StructuralCounts {
    pub functions: usize,
    pub classes: usize,
    pub statements: usize,
    pub comment_lines: usize,
    pub max_nesting_depth: usize,
}

/// Walks `ast` once, tallying structural counters in a single pass.
pub fn compute(ast: &AstNode) -> StructuralCounts {
    let mut counts = StructuralCounts::default();
    walk(ast, 0, &mut counts);
    counts
}

fn walk(node: &AstNode, depth: usize, counts: &mut StructuralCounts) {
    match node.kind() {
        NodeKind::FunctionDef => counts.functions += 1,
        NodeKind::Comment => counts.comment_lines += node.span().line_count() as usize,
        NodeKind::Assignment | NodeKind::VariableDecl => counts.statements += 1,
        NodeKind::Other(kind) => {
            let kind = kind.as_str();
            if CLASS_KINDS.contains(&kind) {
                counts.classes += 1;
            }
            if STATEMENT_KINDS.contains(&kind) {
                counts.statements += 1;
            }
        }
        _ => {}
    }

    let next_depth = match node.kind() {
        NodeKind::Other(kind) if NESTING_KINDS.contains(&kind.as_str()) => depth + 1,
        _ => depth,
    };
    counts.max_nesting_depth = counts.max_nesting_depth.max(next_depth);

    for child in node.children() {
        walk(child, next_depth, counts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::Span;

    fn leaf(kind: NodeKind, text: &str) -> AstNode {
        AstNode::new(kind, Span::new(1, 1, 1, 1), text, vec![])
    }

    fn other(kind: &str, children: Vec<AstNode>) -> AstNode {
        AstNode::new(
            NodeKind::Other(kind.to_string()),
            Span::new(1, 1, 1, 1),
            kind,
            children,
        )
    }

    #[test]
    fn counts_functions_classes_and_statements() {
        // class Foo { fn bar() { if (x) { return 1; } } }
        let tree = other(
            "source_file",
            vec![other(
                "class_declaration",
                vec![AstNode::new(
                    NodeKind::FunctionDef,
                    Span::new(1, 1, 1, 1),
                    "bar",
                    vec![other(
                        "if_statement",
                        vec![other("return_statement", vec![])],
                    )],
                )],
            )],
        );
        let counts = compute(&tree);
        assert_eq!(counts.functions, 1);
        assert_eq!(counts.classes, 1);
        assert_eq!(counts.statements, 2); // if_statement + return_statement
        assert_eq!(counts.max_nesting_depth, 1);
    }

    #[test]
    fn nesting_depth_accumulates_across_levels() {
        // if { for { while { } } }
        let tree = other(
            "if_statement",
            vec![other(
                "for_statement",
                vec![other("while_statement", vec![])],
            )],
        );
        assert_eq!(compute(&tree).max_nesting_depth, 3);
    }

    #[test]
    fn declaration_wrapper_and_inner_variable_decl_count_once() {
        // TypeScript-style: lexical_declaration wraps a VariableDecl child —
        // only the VariableDecl should be counted, not the wrapper too.
        let tree = other(
            "lexical_declaration",
            vec![AstNode::new(
                NodeKind::VariableDecl,
                Span::new(1, 1, 1, 1),
                "y",
                vec![],
            )],
        );
        assert_eq!(compute(&tree).statements, 1);
    }

    #[test]
    fn comment_lines_counts_span_not_node_count() {
        let single_line = leaf(NodeKind::Comment, "// a");
        let multi_line = AstNode::new(
            NodeKind::Comment,
            Span::new(2, 1, 3, 5),
            "/* multi\nline */",
            vec![],
        );
        let tree = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 3, 1),
            "root",
            vec![single_line, multi_line],
        );
        assert_eq!(compute(&tree).comment_lines, 1 + 2);
    }
}
