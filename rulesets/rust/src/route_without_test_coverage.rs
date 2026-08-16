use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use vord_rules_engine::{CrossFileRule, Finding, IssueType, RuleId, RuleMetadata, Severity};

/// axum's HTTP-method combinators: `.route("/path", get(handler))`,
/// `.route("/path", post(handler).delete(other))`, etc. Requiring one of
/// these among the second argument's calls is what tells a real axum route
/// registration apart from an unrelated `.route(...)` method on some other
/// builder that also happens to take a string literal first.
const HTTP_METHOD_NAMES: &[&str] = &["get", "post", "put", "patch", "delete", "head", "options"];

fn other_kind_name(node: &AstNode) -> Option<&str> {
    match node.kind() {
        NodeKind::Other(name) => Some(name.as_ref()),
        _ => None,
    }
}

fn member_method_name(callee: &AstNode) -> Option<&str> {
    match callee.kind() {
        NodeKind::MemberAccess => callee
            .children()
            .iter()
            .rev()
            .find(|c| *c.kind() == NodeKind::Identifier)
            .map(|c| c.text()),
        _ => None,
    }
}

/// The raw text of a Rust string literal, quotes stripped — `"/foo"` ->
/// `/foo` — via its `string_content` child. `None` for anything that isn't
/// a plain string literal (a `format!(...)` path, a constant, ...): this
/// rule only recognizes a route path written directly at the call site.
fn string_literal_text(node: &AstNode) -> Option<&str> {
    if *node.kind() != NodeKind::StringLiteral {
        return None;
    }
    node.children()
        .iter()
        .find(|c| other_kind_name(c) == Some("string_content"))
        .map(|c| c.text())
}

/// Every `.route("/path", <handler>)` registration in `ast`, where the
/// handler argument contains a recognized HTTP-method combinator call.
fn collect_route_registrations(ast: &AstNode, out: &mut Vec<(String, Span)>) {
    for node in ast.descendants() {
        if *node.kind() != NodeKind::Call {
            continue;
        }
        let children = node.children();
        let Some(callee) = children.first() else {
            continue;
        };
        if member_method_name(callee) != Some("route") {
            continue;
        }
        let Some(args) = children.get(1) else {
            continue;
        };
        let Some(path) = args.children().first().and_then(string_literal_text) else {
            continue;
        };
        let has_method_combinator = args.children().iter().skip(1).any(|arg| {
            arg.descendants().any(|n| {
                *n.kind() == NodeKind::Call
                    && n.children().first().is_some_and(|callee| {
                        *callee.kind() == NodeKind::Identifier
                            && HTTP_METHOD_NAMES.contains(&callee.text())
                    })
            })
        });
        if has_method_combinator {
            out.push((path.to_string(), node.span()));
        }
    }
}

/// The substring of `file`'s content that counts as test code: the whole
/// file for a `tests/`-convention integration-test file, or just the lines
/// inside any `#[cfg(test)] mod ... { .. }` block for an ordinary source
/// file — see `vord_rules_engine::is_test_only_path`/`rust_test_module_ranges`,
/// the same split every other rule in this codebase that exempts test code
/// uses.
fn test_text(file: &SourceFile) -> String {
    if vord_rules_engine::is_test_only_path(file.path()) {
        return file.content().to_string();
    }
    let ranges = vord_rules_engine::rust_test_module_ranges(file.content());
    if ranges.is_empty() {
        return String::new();
    }
    file.content()
        .lines()
        .enumerate()
        .filter(|(zero_based, _)| vord_rules_engine::in_ranges(&ranges, *zero_based as u32 + 1))
        .map(|(_, line)| line)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Flags an axum route registered this scan with no string literal
/// matching its path anywhere in the project's test code — "you added a
/// door, does anything walk through it". Not behavioral coverage (it can't
/// tell a real request test from a coincidental string match), just the
/// cheap floor: is the path spelled out anywhere a test could plausibly be
/// exercising it.
pub struct RouteWithoutTestCoverageRule {
    id: RuleId,
}

impl RouteWithoutTestCoverageRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("rust:route-without-test-coverage").expect("valid rule id"),
        }
    }
}

impl Default for RouteWithoutTestCoverageRule {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileRule for RouteWithoutTestCoverageRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "An axum `.route(\"/path\", ..)` registration whose path string never \
                appears anywhere in the project's test code — a route with no test walking \
                through it."
                .into(),
            tags: vec!["rust".into(), "test-coverage".into(), "axum".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, files: &[(SourceFile, AstNode)]) -> Vec<(usize, Finding)> {
        let rust = LanguageIdentifier::rust();
        let corpus: String = files
            .iter()
            .filter(|(file, _)| *file.language() == rust)
            .map(|(file, _)| test_text(file))
            .collect::<Vec<_>>()
            .join("\n");

        files
            .iter()
            .enumerate()
            .filter(|(_, (file, _))| {
                *file.language() == rust && !vord_rules_engine::is_test_only_path(file.path())
            })
            .flat_map(|(index, (_, ast))| {
                let mut routes = Vec::new();
                collect_route_registrations(ast, &mut routes);
                let corpus = &corpus;
                routes.into_iter().filter_map(move |(path, span)| {
                    let needle = format!("\"{path}\"");
                    if corpus.contains(&needle) {
                        None
                    } else {
                        Some((
                            index,
                            Finding::new(
                                format!(
                                    "route \"{path}\" registered here, but no test in the project references this path"
                                ),
                                span,
                            ),
                        ))
                    }
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    use super::*;

    fn parse(path: &str, code: &str) -> (SourceFile, AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::rust()).unwrap();
        let ast = vord_parser_rust::RustParser::new().parse(&file).unwrap();
        (file, ast)
    }

    #[test]
    fn flags_a_route_with_no_matching_test_literal_anywhere() {
        let main = parse(
            "src/main.rs",
            "fn app() -> Router {\n    Router::new()\n        .route(\"/api/v1/admin/calibrate\", post(calibrate_handler))\n}\n",
        );
        let test = parse(
            "src/handler.rs",
            "#[cfg(test)]\nmod tests {\n    #[test]\n    fn fits() {\n        assert_eq!(fit_sigmoid_params(&[]).converged, false);\n    }\n}\n",
        );
        let files = vec![main, test];

        let findings = RouteWithoutTestCoverageRule::new().check(&files);
        assert_eq!(findings.len(), 1);
        let (index, finding) = &findings[0];
        assert_eq!(files[*index].0.path(), "src/main.rs");
        assert!(finding.message.contains("/api/v1/admin/calibrate"));
    }

    #[test]
    fn silent_when_an_inline_test_module_references_the_path() {
        let main = parse(
            "src/main.rs",
            "fn app() -> Router {\n    Router::new()\n        .route(\"/api/v1/admin/calibrate\", post(calibrate_handler))\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn hits_the_route() {\n        let res = call(\"/api/v1/admin/calibrate\");\n    }\n}\n",
        );
        let files = vec![main];

        assert!(RouteWithoutTestCoverageRule::new().check(&files).is_empty());
    }

    #[test]
    fn silent_when_a_separate_integration_test_file_references_the_path() {
        let main = parse(
            "src/main.rs",
            "fn app() -> Router {\n    Router::new()\n        .route(\"/api/v1/admin/calibrate\", post(calibrate_handler))\n}\n",
        );
        let integration_test = parse(
            "tests/api.rs",
            "#[test]\nfn calibrate_endpoint_works() {\n    let res = client.post(\"/api/v1/admin/calibrate\").send();\n}\n",
        );
        let files = vec![main, integration_test];

        assert!(RouteWithoutTestCoverageRule::new().check(&files).is_empty());
    }

    #[test]
    fn silent_on_a_route_call_with_no_http_method_combinator() {
        // A `.route(...)` on some unrelated builder that isn't axum's
        // routing DSL shouldn't be treated as an endpoint registration.
        let main = parse(
            "src/main.rs",
            "fn plan() -> Plan {\n    Planner::new().route(\"/api/v1/admin/calibrate\", waypoint)\n}\n",
        );
        let files = vec![main];

        assert!(RouteWithoutTestCoverageRule::new().check(&files).is_empty());
    }

    #[test]
    fn ignores_non_rust_files() {
        let ts_file = SourceFile::new(
            "src/app.ts",
            "app.route(\"/api/v1/admin/calibrate\", post(calibrateHandler));",
            LanguageIdentifier::typescript(),
        )
        .unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&ts_file)
            .unwrap();
        let files = vec![(ts_file, ast)];

        assert!(RouteWithoutTestCoverageRule::new().check(&files).is_empty());
    }
}
