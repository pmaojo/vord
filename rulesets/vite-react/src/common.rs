//! Shared helpers for this crate's rules: the bulletproof-react directory
//! vocabulary (`src/components`, `src/features/<feature>/{api,hooks}`,
//! `src/infra`) read off path topology — the same "curated, not inferred"
//! posture `vord_import_graph::infra_roster` takes, just scoped to one
//! starter's own layered convention instead of the generic hexagon — plus
//! the small JSX/call-expression AST helpers this crate needs that
//! `rulesets/react::common` doesn't expose (private to that crate).

use globset::{Glob, GlobSet, GlobSetBuilder};
use vord_ast::{AstNode, NodeKind};

pub(crate) fn is_other(node: &AstNode, kind: &str) -> bool {
    matches!(node.kind(), NodeKind::Other(k) if k.as_ref() == kind)
}

pub(crate) fn strip_quotes(text: &str) -> String {
    text.trim_matches(|c| c == '\'' || c == '"' || c == '`')
        .to_string()
}

/// Compiles a rule's `[vite_react.exceptions]` globs, silently dropping any
/// pattern `globset` itself rejects — a typo'd exception must not crash the
/// scan, only fail to except the path it meant to.
pub(crate) fn build_globset(patterns: &[String]) -> GlobSet {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }
    builder.build().unwrap_or_else(|_| {
        GlobSetBuilder::new()
            .build()
            .expect("an empty globset always builds")
    })
}

pub(crate) fn is_excepted(path: &str, exceptions: &GlobSet) -> bool {
    exceptions.is_match(path)
}

fn segments(path: &str) -> Vec<&str> {
    path.split(['/', '\\']).filter(|s| !s.is_empty()).collect()
}

fn contains_subsequence(haystack: &[&str], needle: &[&str]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// True once a path contains `.../features/<any-feature>/<dir>/...` —
/// `<dir>` is any of this convention's per-feature subdirectories
/// (`components`, `api`, `hooks`).
fn is_under_feature_dir(path: &str, dir: &str) -> bool {
    let s = segments(path);
    s.iter()
        .enumerate()
        .any(|(i, seg)| *seg == "features" && s.get(i + 2) == Some(&dir))
}

/// `src/components/**` or `src/features/<feature>/components/**` — the
/// presentational layer: it renders, it does not fetch or hold global state.
pub(crate) fn is_view_path(path: &str) -> bool {
    contains_subsequence(&segments(path), &["src", "components"])
        || is_under_feature_dir(path, "components")
}

/// `src/features/<feature>/hooks/**`.
pub(crate) fn is_feature_hooks_path(path: &str) -> bool {
    is_under_feature_dir(path, "hooks")
}

/// `src/features/<feature>/api/**`.
pub(crate) fn is_feature_api_path(path: &str) -> bool {
    is_under_feature_dir(path, "api")
}

/// `src/infra/**` — the one place allowed to know about `axios`/`fetch`
/// directly.
pub(crate) fn is_infra_path(path: &str) -> bool {
    contains_subsequence(&segments(path), &["src", "infra"])
}

/// A specifier that reaches into a `src/infra/**` module: relative
/// (`../infra/http`, `./infra/http`) or alias (`@/infra/http`) import
/// forms — the same set `is_infra_path` recognizes for a file's own
/// location, applied to what it imports instead.
pub(crate) fn is_infra_specifier(specifier: &str) -> bool {
    contains_subsequence(
        &specifier
            .split(['/', '\\'])
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        &["infra"],
    )
}

/// Spans of every `import type { ... } from '...'` / `export type { ... }
/// from '...'` statement in `ast` — a type-only import is erased at compile
/// time, so it carries none of the runtime coupling these rules exist to
/// catch (a component typing a prop as `QueryClient` is not calling React
/// Query). `imported_modules` doesn't distinguish the two, so callers that
/// care check a hit's span against this set themselves.
pub(crate) fn is_type_only_import_span(ast: &AstNode, span: vord_ast::Span) -> bool {
    ast.descendants().any(|node| {
        (is_other(node, "import_statement") || is_other(node, "export_statement"))
            && node.span() == span
            && {
                let text = node.text().trim_start();
                text.starts_with("import type") || text.starts_with("export type")
            }
    })
}

/// A path whose name marks it as configuration rather than application
/// code (`vite.config.ts`, `src/config/env.ts`, `tailwind.config.js`) — the
/// literal it holds is a deliberate, single-source-of-truth constant, not
/// the kind of scattered hardcoding these rules exist to catch.
pub(crate) fn is_config_path(path: &str) -> bool {
    path.to_ascii_lowercase().contains("config")
}

// -- JSX helpers (own copies: `rulesets/react::common` is private to that
// crate) --

pub(crate) fn is_jsx_kind(node: &AstNode) -> bool {
    matches!(
        node.kind(),
        NodeKind::Other(k) if matches!(k.as_ref(), "jsx_element" | "jsx_self_closing_element" | "jsx_fragment")
    )
}

fn opening_tag(el: &AstNode) -> Option<&AstNode> {
    if is_other(el, "jsx_self_closing_element") {
        return Some(el);
    }
    if is_other(el, "jsx_element") {
        return el
            .children()
            .first()
            .filter(|c| is_other(c, "jsx_opening_element"));
    }
    None
}

fn attribute_name(attr: &AstNode) -> Option<&str> {
    let name_node = attr.first_child()?;
    (*name_node.kind() == NodeKind::Identifier).then(|| name_node.text())
}

fn attribute_value(attr: &AstNode) -> Option<&AstNode> {
    attr.children().get(1)
}

/// The `className`/`class` attribute's string content, if it's a plain
/// string (not a `clsx(...)`/template expression this rule doesn't try to
/// evaluate).
pub(crate) fn class_attribute_text(el: &AstNode) -> Option<String> {
    let tag = opening_tag(el)?;
    let attr = tag
        .children()
        .iter()
        .filter(|c| is_other(c, "jsx_attribute"))
        .find(|a| matches!(attribute_name(a), Some("className") | Some("class")))?;
    let value = attribute_value(attr)?;
    (*value.kind() == NodeKind::StringLiteral).then(|| strip_quotes(value.text()))
}

pub(crate) fn class_attribute_span(el: &AstNode) -> Option<vord_ast::Span> {
    let tag = opening_tag(el)?;
    let attr = tag
        .children()
        .iter()
        .filter(|c| is_other(c, "jsx_attribute"))
        .find(|a| matches!(attribute_name(a), Some("className") | Some("class")))?;
    Some(attr.span())
}
