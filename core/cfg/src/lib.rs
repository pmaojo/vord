//! Control Flow Graph (CFG), Static Single Assignment (SSA), and Control Dependence Graph (CDG) crate.

pub mod cdg;
pub mod cfg;
pub mod ssa;

pub use cdg::ControlDependenceGraph;
pub use cfg::{BasicBlock, ControlFlowGraph, EdgeKind};
pub use ssa::{PhiNode, SsaForm};
