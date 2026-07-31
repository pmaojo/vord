//! Rule: flags a token/password/secret/session-named value built from
//! `math/rand`. `math/rand`'s generator is a deterministic PRNG (seeded
//! from wall-clock time unless seeded explicitly) — predictable enough to
//! reconstruct or brute-force — so building a security-sensitive value from
//! it is a real vulnerability; use `crypto/rand` instead. Scoped to method
//! names `math/rand` alone exposes (`Intn`, `Int63`, `Int31`, `Float64`,
//! `Float32`, `Perm`, `Shuffle`, `Int63n`, `Int31n`, `NormFloat64`,
//! `ExpFloat64`) — deliberately excluding `Int`/`Read`, which `crypto/rand`
//! also exposes under the same package-alias name `rand`, so a syntactic
//! check without import resolution can't tell which package a bare
//! `rand.Int(...)`/`rand.Read(...)` call means. Mirrors
//! `php:weak-random-token`/`typescript:math-random-for-token`'s naming-
//! heuristic shape.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use yunq_rules_engine::{
    Finding, IssueType, Rule, RuleId, RuleMetadata, Severity, declare_rule_id,
};

const SENSITIVE_NAME_MARKERS: &[&str] =
    &["token", "password", "passwd", "secret", "apikey", "session"];

const MATH_RAND_ONLY_METHODS: &[&str] = &[
    "Intn",
    "Int63",
    "Int31",
    "Float64",
    "Float32",
    "Perm",
    "Shuffle",
    "Int63n",
    "Int31n",
    "NormFloat64",
    "ExpFloat64",
];

fn looks_sensitive(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_NAME_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn uses_weak_random(value: &AstNode) -> bool {
    MATH_RAND_ONLY_METHODS
        .iter()
        .any(|method| value.subtree_contains_text(&format!("rand.{method}(")))
}

/// `short_var_declaration`/`assignment_statement` both wrap `[names,
/// values]`, each an `expression_list` (verified against real parses) — so
/// unlike PHP/TS's direct `[target, value, ...]` shape, the target
/// identifier is one level deeper. Scoped to a single-name target
/// (`names.children().len() == 1`) to sidestep the ambiguity of which of
/// several tuple-assigned names the flagged value belongs to.
fn flagged_target(decl: &AstNode) -> Option<&AstNode> {
    if !matches!(decl.kind(), NodeKind::VariableDecl | NodeKind::Assignment) {
        return None;
    }
    let [names, values] = decl.children() else {
        return None;
    };
    if names.children().len() != 1 {
        return None;
    }
    let target = names.children().first()?;
    if *target.kind() != NodeKind::Identifier || !looks_sensitive(target.text()) {
        return None;
    }
    uses_weak_random(values).then_some(target)
}

declare_rule_id!(WeakRandomTokenRule, "go:weak-random-token");

impl Rule for WeakRandomTokenRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        *language == LanguageIdentifier::go()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "`math/rand` is not cryptographically secure; using it to build a \
                token, password, secret, API key, or session id makes that value predictable. \
                Use `crypto/rand` instead."
                .into(),
            tags: vec!["security".into(), "go".into()],
            cwe: Some(338),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter_map(flagged_target)
            .map(|target| {
                Finding::new(
                    format!(
                        "`{}` is built from `math/rand`, which is not cryptographically secure; \
                        use `crypto/rand` instead",
                        target.text()
                    ),
                    target.span(),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use yunq_ast::SourceFile;
    use yunq_rules_engine::AstParser;

    use super::*;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.go", code, LanguageIdentifier::go()).unwrap();
        let ast = yunq_parser_go::GoParser::new().parse(&file).unwrap();
        WeakRandomTokenRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_token_from_math_rand_intn() {
        assert_eq!(
            check("package main\nfunc f() {\n\ttoken := rand.Intn(1000000)\n}\n").len(),
            1
        );
    }

    #[test]
    fn flags_session_id_assignment() {
        assert_eq!(
            check("package main\nfunc f() {\n\tvar sessionId string\n\tsessionId = strconv.Itoa(rand.Int63())\n}\n").len(),
            1
        );
    }

    #[test]
    fn ignores_ambiguous_rand_int_and_read() {
        // `rand.Int`/`rand.Read` exist on both math/rand and crypto/rand under
        // the same package alias `rand` — deliberately not flagged, since a
        // syntactic check can't tell which package is imported.
        assert!(check("package main\nfunc f() {\n\ttoken := rand.Read(buf)\n}\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_variable_names() {
        assert!(check("package main\nfunc f() {\n\tjitter := rand.Intn(100)\n}\n").is_empty());
    }

    #[test]
    fn ignores_tuple_assignment_targets() {
        assert!(check("package main\nfunc f() {\n\ttoken, err := generate()\n}\n").is_empty());
    }
}
