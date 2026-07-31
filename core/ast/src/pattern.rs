//! Tree-sitter S-Expression Pattern Matching Engine with captures and predicate evaluations.

use crate::{AstNode, NodeKind};
use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicate {
    Eq(String, String),
    NotEq(String, String),
    Match(String, String),
}

#[derive(Debug, Clone)]
pub struct PatternNode {
    pub kind_name: String,
    pub capture: Option<String>,
    pub children: Vec<PatternNode>,
}

#[derive(Debug, Clone)]
pub struct Pattern {
    pub root: PatternNode,
    pub predicates: Vec<Predicate>,
}

#[derive(Debug, Clone)]
pub struct MatchResult<'a> {
    pub root: &'a AstNode,
    pub captures: HashMap<String, &'a AstNode>,
}

#[derive(Debug, thiserror::Error)]
pub enum PatternParseError {
    #[error("empty s-expression")]
    Empty,
    #[error("unmatched parenthesis in pattern: {0}")]
    UnmatchedParen(String),
    #[error("invalid predicate format: {0}")]
    InvalidPredicate(String),
    #[error("regex compilation error: {0}")]
    RegexError(#[from] regex::Error),
}

impl Pattern {
    /// Parses a Tree-sitter style S-expression string into a Pattern.
    /// Example: `(Call (Identifier) @fn (#eq? @fn "eval"))`
    pub fn parse(input: &str) -> Result<Self, PatternParseError> {
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Err(PatternParseError::Empty);
        }
        let mut idx = 0;
        let mut predicates = Vec::new();
        let root = parse_pattern_node(&tokens, &mut idx, &mut predicates)?;

        // Parse remaining predicates if any
        while idx < tokens.len() {
            if tokens[idx] == "(" && idx + 1 < tokens.len() && tokens[idx + 1].starts_with('#') {
                parse_predicate(&tokens, &mut idx, &mut predicates)?;
            } else {
                idx += 1;
            }
        }

        Ok(Pattern { root, predicates })
    }

    /// Matches the pattern recursively against an `AstNode` and its subtree,
    /// returning all matching node results with variable captures.
    pub fn find_matches<'a>(&self, root: &'a AstNode) -> Vec<MatchResult<'a>> {
        let mut matches = Vec::new();
        self.collect_matches(root, &mut matches);
        matches
    }

    fn collect_matches<'a>(&self, node: &'a AstNode, out: &mut Vec<MatchResult<'a>>) {
        let mut captures = HashMap::new();
        if match_node(&self.root, node, &mut captures) && self.evaluate_predicates(&captures) {
            out.push(MatchResult {
                root: node,
                captures,
            });
        }
        for child in node.children() {
            self.collect_matches(child, out);
        }
    }

    fn evaluate_predicates(&self, captures: &HashMap<String, &AstNode>) -> bool {
        for pred in &self.predicates {
            match pred {
                Predicate::Eq(var, val) => {
                    let text = get_val(var, captures);
                    let target = resolve_target(val, captures);
                    if text != target {
                        return false;
                    }
                }
                Predicate::NotEq(var, val) => {
                    let text = get_val(var, captures);
                    let target = resolve_target(val, captures);
                    if text == target {
                        return false;
                    }
                }
                Predicate::Match(var, regex_str) => {
                    let text = get_val(var, captures);
                    if let Ok(re) = Regex::new(regex_str) {
                        if !re.is_match(&text) {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn match_node<'a>(
    pat: &PatternNode,
    node: &'a AstNode,
    captures: &mut HashMap<String, &'a AstNode>,
) -> bool {
    let node_kind_str = match node.kind() {
        NodeKind::Other(k) => k.to_string(),
        kind => format!("{:?}", kind),
    };

    if pat.kind_name != "_" && !pat.kind_name.eq_ignore_ascii_case(&node_kind_str) {
        return false;
    }

    if let Some(ref cap) = pat.capture {
        captures.insert(cap.clone(), node);
    }

    if pat.children.is_empty() {
        return true;
    }

    let children = node.children();
    if children.len() < pat.children.len() {
        return false;
    }

    let mut child_idx = 0;
    for pat_child in &pat.children {
        let mut matched = false;
        while child_idx < children.len() {
            if match_node(pat_child, &children[child_idx], captures) {
                matched = true;
                child_idx += 1;
                break;
            }
            child_idx += 1;
        }
        if !matched {
            return false;
        }
    }

    true
}

fn get_val(var: &str, captures: &HashMap<String, &AstNode>) -> String {
    if let Some(node) = captures.get(var) {
        node.text().to_string()
    } else {
        var.to_string()
    }
}

fn resolve_target(val: &str, captures: &HashMap<String, &AstNode>) -> String {
    let unquoted = val.trim_matches('"');
    if unquoted.starts_with('@') {
        get_val(unquoted, captures)
    } else {
        unquoted.to_string()
    }
}

fn tokenize(input: &str) -> Result<Vec<String>, PatternParseError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut buf = String::new();

    while let Some(&c) = chars.peek() {
        match c {
            '(' | ')' => {
                if !buf.trim().is_empty() {
                    tokens.push(buf.trim().to_string());
                    buf.clear();
                }
                tokens.push(c.to_string());
                chars.next();
            }
            '"' => {
                if !buf.trim().is_empty() {
                    tokens.push(buf.trim().to_string());
                    buf.clear();
                }
                buf.push(c);
                chars.next();
                while let Some(&nc) = chars.peek() {
                    buf.push(nc);
                    chars.next();
                    if nc == '"' {
                        break;
                    }
                }
                tokens.push(buf.clone());
                buf.clear();
            }
            c if c.is_whitespace() => {
                if !buf.trim().is_empty() {
                    tokens.push(buf.trim().to_string());
                    buf.clear();
                }
                chars.next();
            }
            _ => {
                buf.push(c);
                chars.next();
            }
        }
    }
    if !buf.trim().is_empty() {
        tokens.push(buf.trim().to_string());
    }
    Ok(tokens)
}

fn parse_pattern_node(
    tokens: &[String],
    idx: &mut usize,
    predicates: &mut Vec<Predicate>,
) -> Result<PatternNode, PatternParseError> {
    if *idx >= tokens.len() || tokens[*idx] != "(" {
        return Err(PatternParseError::UnmatchedParen("Expected '('".into()));
    }
    *idx += 1; // skip '('

    if *idx < tokens.len() && tokens[*idx].starts_with('#') {
        parse_predicate(tokens, idx, predicates)?;
        return Err(PatternParseError::Empty);
    }

    if *idx >= tokens.len() {
        return Err(PatternParseError::UnmatchedParen("Unexpected EOF".into()));
    }

    let kind_name = tokens[*idx].clone();
    *idx += 1;

    let mut capture = None;
    let mut children = Vec::new();

    while *idx < tokens.len() && tokens[*idx] != ")" {
        if tokens[*idx] == "(" {
            if *idx + 1 < tokens.len() && tokens[*idx + 1].starts_with('#') {
                parse_predicate(tokens, idx, predicates)?;
            } else {
                let mut child = parse_pattern_node(tokens, idx, predicates)?;
                if *idx < tokens.len() && tokens[*idx].starts_with('@') {
                    child.capture = Some(tokens[*idx].clone());
                    *idx += 1;
                }
                children.push(child);
            }
        } else if tokens[*idx].starts_with('@') {
            capture = Some(tokens[*idx].clone());
            *idx += 1;
        } else {
            *idx += 1;
        }
    }

    if *idx < tokens.len() && tokens[*idx] == ")" {
        *idx += 1; // skip ')'
    }

    Ok(PatternNode {
        kind_name,
        capture,
        children,
    })
}

fn parse_predicate(
    tokens: &[String],
    idx: &mut usize,
    predicates: &mut Vec<Predicate>,
) -> Result<(), PatternParseError> {
    if *idx >= tokens.len() || tokens[*idx] != "(" {
        return Err(PatternParseError::UnmatchedParen(
            "Expected '(' for predicate".into(),
        ));
    }
    *idx += 1; // skip '('

    let pred_name = tokens[*idx].clone();
    *idx += 1;

    let mut args = Vec::new();
    while *idx < tokens.len() && tokens[*idx] != ")" {
        args.push(tokens[*idx].clone());
        *idx += 1;
    }
    if *idx < tokens.len() && tokens[*idx] == ")" {
        *idx += 1; // skip ')'
    }

    if args.len() < 2 {
        return Err(PatternParseError::InvalidPredicate(pred_name));
    }

    match pred_name.as_str() {
        "#eq?" => predicates.push(Predicate::Eq(args[0].clone(), args[1].clone())),
        "#not-eq?" => predicates.push(Predicate::NotEq(args[0].clone(), args[1].clone())),
        "#match?" => predicates.push(Predicate::Match(
            args[0].clone(),
            args[1].trim_matches('"').to_string(),
        )),
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Span;

    #[test]
    fn parses_and_matches_pattern_with_predicates() {
        let fn_id = AstNode::new(NodeKind::Identifier, Span::new(1, 1, 1, 5), "eval", vec![]);
        let call_node = AstNode::new(
            NodeKind::Call,
            Span::new(1, 1, 1, 10),
            "eval()",
            vec![fn_id],
        );

        let pattern = Pattern::parse("(Call (Identifier) @fn (#eq? @fn \"eval\"))").unwrap();
        let matches = pattern.find_matches(&call_node);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].captures.get("@fn").unwrap().text(), "eval");
    }

    #[test]
    fn rejects_non_matching_predicates() {
        let fn_id = AstNode::new(
            NodeKind::Identifier,
            Span::new(1, 1, 1, 5),
            "safe_fn",
            vec![],
        );
        let call_node = AstNode::new(
            NodeKind::Call,
            Span::new(1, 1, 1, 10),
            "safe_fn()",
            vec![fn_id],
        );

        let pattern = Pattern::parse("(Call (Identifier) @fn (#eq? @fn \"eval\"))").unwrap();
        let matches = pattern.find_matches(&call_node);
        assert!(matches.is_empty());
    }
}
