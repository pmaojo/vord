//! Inbound adapter: Dockerfile → neutral AST.
//!
//! The upstream Dockerfile grammar is pinned to Tree-sitter 0.20 while the
//! workspace uses 0.25. A line-oriented adapter covers the instructions vord
//! currently models and avoids linking incompatible Tree-sitter ABIs.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{AstParser, ParseError};

pub struct DockerfileParser;

impl DockerfileParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DockerfileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl AstParser for DockerfileParser {
    fn language(&self) -> LanguageIdentifier {
        LanguageIdentifier::dockerfile()
    }

    fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
        let source = file.content_shared();
        let mut children = Vec::new();
        let mut offset = 0;
        for (row, line) in file.content().split_inclusive('\n').enumerate() {
            let content = line.trim_end_matches('\n').trim_end_matches('\r');
            let trimmed = content.trim_start();
            let kind = if trimmed.starts_with('#') {
                Some(NodeKind::Comment)
            } else if matches!(
                trimmed.split_ascii_whitespace().next(),
                Some("FROM" | "RUN" | "CMD")
            ) {
                Some(NodeKind::FunctionDef)
            } else {
                None
            };
            if let Some(kind) = kind {
                children.push(AstNode::from_source(
                    kind,
                    Span::new(row as u32 + 1, 1, row as u32 + 1, content.len() as u32 + 1),
                    std::sync::Arc::clone(&source),
                    offset..offset + content.len(),
                    Vec::new(),
                ));
            }
            offset += line.len();
        }
        let line_count = file.content().lines().count().max(1) as u32;
        Ok(AstNode::from_source(
            NodeKind::SourceUnit,
            Span::new(1, 1, line_count, 1),
            source,
            0..file.content().len(),
            children,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("Dockerfile", code, LanguageIdentifier::dockerfile()).unwrap();
        DockerfileParser::new().parse(&file).unwrap()
    }

    #[test]
    fn maps_dockerfile_concepts() {
        let ast = parse("# syntax=docker/dockerfile:1\nFROM alpine:3.18\nRUN echo hello\n");
        assert_eq!(ast.kind(), &NodeKind::SourceUnit);
        assert_eq!(ast.find_all(&NodeKind::Comment).len(), 1);
        assert_eq!(ast.find_all(&NodeKind::FunctionDef).len(), 2);
    }
}
