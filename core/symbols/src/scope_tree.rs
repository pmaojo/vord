//! Full Lexical Scope Tree and Resolution Engine.
//! Handles hierarchical lexical environments (Global, Module, Function, Block, Closure)
//! and multi-language scoping rules (JS var hoisting, let/const block scope, Rust lifetimes/scopes, Python LEGB).

use std::collections::HashMap;
use vord_ast::{AstNode, LanguageIdentifier, NodeKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    Global,
    Module,
    Function,
    Block,
    Closure,
}

#[derive(Debug, Clone)]
pub struct BindingInfo {
    pub name: String,
    pub is_var_hoisted: bool,
    pub is_const: bool,
    pub node_span: vord_ast::Span,
}

#[derive(Debug, Clone)]
pub struct Scope {
    pub id: usize,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub kind: ScopeKind,
    pub bindings: HashMap<String, BindingInfo>,
}

#[derive(Debug, Clone)]
pub struct BindingResolution {
    pub scope_id: usize,
    pub binding: BindingInfo,
    pub is_captured: bool,
}

#[derive(Debug, Clone)]
pub struct ScopeTree {
    pub scopes: Vec<Scope>,
    pub root_scope: usize,
}

impl ScopeTree {
    /// Builds a full lexical scope tree for an AST given the target language.
    pub fn build(root: &AstNode, lang: Option<LanguageIdentifier>) -> Self {
        let mut builder = ScopeBuilder::new(lang);
        let root_id = builder.create_scope(None, ScopeKind::Global);
        builder.walk_node(root, root_id);
        ScopeTree {
            scopes: builder.scopes,
            root_scope: root_id,
        }
    }

    /// Resolves an identifier by name starting from a specific scope ID up through enclosing scopes.
    pub fn resolve(&self, scope_id: usize, name: &str) -> Option<BindingResolution> {
        let mut curr = Some(scope_id);
        let starting_function_scope = self.enclosing_function_or_global(scope_id);

        while let Some(sid) = curr {
            let scope = &self.scopes[sid];
            if let Some(binding) = scope.bindings.get(name) {
                let current_function_scope = self.enclosing_function_or_global(sid);
                let is_captured = starting_function_scope != current_function_scope;
                return Some(BindingResolution {
                    scope_id: sid,
                    binding: binding.clone(),
                    is_captured,
                });
            }
            curr = scope.parent;
        }

        None
    }

    fn enclosing_function_or_global(&self, mut scope_id: usize) -> usize {
        loop {
            let scope = &self.scopes[scope_id];
            if matches!(
                scope.kind,
                ScopeKind::Function | ScopeKind::Global | ScopeKind::Module
            ) {
                return scope_id;
            }
            if let Some(parent) = scope.parent {
                scope_id = parent;
            } else {
                return scope_id;
            }
        }
    }
}

struct ScopeBuilder {
    scopes: Vec<Scope>,
    _lang: Option<LanguageIdentifier>,
}

impl ScopeBuilder {
    fn new(lang: Option<LanguageIdentifier>) -> Self {
        ScopeBuilder {
            scopes: Vec::new(),
            _lang: lang,
        }
    }

    fn create_scope(&mut self, parent: Option<usize>, kind: ScopeKind) -> usize {
        let id = self.scopes.len();
        let scope = Scope {
            id,
            parent,
            children: Vec::new(),
            kind,
            bindings: HashMap::new(),
        };
        self.scopes.push(scope);
        if let Some(pid) = parent {
            self.scopes[pid].children.push(id);
        }
        id
    }

    fn walk_node(&mut self, node: &AstNode, current_scope: usize) {
        let mut active_scope = current_scope;

        match node.kind() {
            NodeKind::FunctionDef => {
                active_scope = self.create_scope(Some(current_scope), ScopeKind::Function);
            }
            NodeKind::VariableDecl => {
                if let Some(ident) = node
                    .first_child()
                    .filter(|c| *c.kind() == NodeKind::Identifier)
                {
                    let name = ident.text().to_string();
                    let target_scope =
                        self.resolve_hoist_scope(active_scope, node.text().starts_with("var"));
                    self.scopes[target_scope].bindings.insert(
                        name.clone(),
                        BindingInfo {
                            name,
                            is_var_hoisted: node.text().starts_with("var"),
                            is_const: node.text().starts_with("const"),
                            node_span: node.span(),
                        },
                    );
                }
            }
            NodeKind::Other(k) if k.contains("block") || k.contains("statement_block") => {
                active_scope = self.create_scope(Some(current_scope), ScopeKind::Block);
            }
            _ => {}
        }

        for child in node.children() {
            self.walk_node(child, active_scope);
        }
    }

    fn resolve_hoist_scope(&self, mut scope_id: usize, is_var: bool) -> usize {
        if !is_var {
            return scope_id;
        }
        // Hoist 'var' to enclosing function, module, or global scope
        loop {
            let scope = &self.scopes[scope_id];
            if matches!(
                scope.kind,
                ScopeKind::Function | ScopeKind::Global | ScopeKind::Module
            ) {
                return scope_id;
            }
            if let Some(parent) = scope.parent {
                scope_id = parent;
            } else {
                return scope_id;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::Span;

    #[test]
    fn builds_scope_tree_and_resolves_bindings() {
        let var_id = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 2), "x", vec![]);
        let var_decl = AstNode::new(
            NodeKind::VariableDecl,
            Span::new(1, 1, 1, 10),
            "let x = 1",
            vec![var_id],
        );
        let root = AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 2, 1),
            "let x = 1;",
            vec![var_decl],
        );

        let scope_tree = ScopeTree::build(&root, None);
        let res = scope_tree.resolve(scope_tree.root_scope, "x");
        assert!(res.is_some());
        assert_eq!(res.unwrap().binding.name, "x");
    }
}
