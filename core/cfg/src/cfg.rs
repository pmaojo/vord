//! Control Flow Graph (CFG) Construction.

use std::collections::HashMap;
use yunq_ast::AstNode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    Fallthrough,
    BranchTrue,
    BranchFalse,
    Jump,
    Exception,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    pub statements: Vec<AstNode>,
    pub predecessors: Vec<(usize, EdgeKind)>,
    pub successors: Vec<(usize, EdgeKind)>,
}

#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub entry: usize,
    pub exit: usize,
    pub blocks: HashMap<usize, BasicBlock>,
}

impl ControlFlowGraph {
    /// Builds a Control Flow Graph for a function or method AST node.
    pub fn build(func_node: &AstNode) -> Self {
        let mut builder = CfgBuilder::new();
        let entry = builder.create_block();
        let exit = builder.create_block();

        let current = builder.build_sub_ast(func_node, entry, exit);
        builder.add_edge(current, exit, EdgeKind::Fallthrough);

        ControlFlowGraph {
            entry,
            exit,
            blocks: builder.blocks,
        }
    }
}

struct CfgBuilder {
    next_id: usize,
    blocks: HashMap<usize, BasicBlock>,
}

impl CfgBuilder {
    fn new() -> Self {
        CfgBuilder {
            next_id: 0,
            blocks: HashMap::new(),
        }
    }

    fn create_block(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.blocks.insert(
            id,
            BasicBlock {
                id,
                statements: Vec::new(),
                predecessors: Vec::new(),
                successors: Vec::new(),
            },
        );
        id
    }

    fn add_edge(&mut self, from: usize, to: usize, kind: EdgeKind) {
        if let Some(b) = self.blocks.get_mut(&from) {
            b.successors.push((to, kind));
        }
        if let Some(b) = self.blocks.get_mut(&to) {
            b.predecessors.push((from, kind));
        }
    }

    fn build_sub_ast(&mut self, node: &AstNode, current: usize, exit: usize) -> usize {
        let kind_str = match node.kind() {
            yunq_ast::NodeKind::Other(k) => k.to_string(),
            k => format!("{:?}", k),
        };

        if kind_str.contains("if") || kind_str.contains("branch") {
            let true_blk = self.create_block();
            let false_blk = self.create_block();
            let join_blk = self.create_block();

            self.add_edge(current, true_blk, EdgeKind::BranchTrue);
            self.add_edge(current, false_blk, EdgeKind::BranchFalse);

            let children = node.children();
            if let Some(cond_body) = children.first() {
                let end_true = self.build_sub_ast(cond_body, true_blk, exit);
                self.add_edge(end_true, join_blk, EdgeKind::Jump);
            } else {
                self.add_edge(true_blk, join_blk, EdgeKind::Jump);
            }

            if let Some(else_body) = children.get(1) {
                let end_false = self.build_sub_ast(else_body, false_blk, exit);
                self.add_edge(end_false, join_blk, EdgeKind::Jump);
            } else {
                self.add_edge(false_blk, join_blk, EdgeKind::Jump);
            }

            join_blk
        } else if kind_str.contains("return") {
            if let Some(blk) = self.blocks.get_mut(&current) {
                blk.statements.push(node.clone());
            }
            self.add_edge(current, exit, EdgeKind::Jump);
            self.create_block() // Unreachable block after return
        } else if kind_str.contains("try") || kind_str.contains("catch") {
            let try_blk = self.create_block();
            let catch_blk = self.create_block();
            let join_blk = self.create_block();

            self.add_edge(current, try_blk, EdgeKind::Fallthrough);
            self.add_edge(try_blk, catch_blk, EdgeKind::Exception);

            let end_try = self.build_sub_ast(node, try_blk, exit);
            self.add_edge(end_try, join_blk, EdgeKind::Jump);
            self.add_edge(catch_blk, join_blk, EdgeKind::Jump);

            join_blk
        } else {
            if let Some(blk) = self.blocks.get_mut(&current) {
                blk.statements.push(node.clone());
            }
            let mut curr = current;
            for child in node.children() {
                curr = self.build_sub_ast(child, curr, exit);
            }
            curr
        }
    }
}
