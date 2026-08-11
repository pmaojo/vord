//! The built-in "vord way" profile (issue #22): a curated, sensible
//! rule-activation baseline per language, active for any project with no
//! explicit profile assignment.
//!
//! This crate can't depend on the ruleset crates (`rulesets/*`) or
//! `core/rules-engine` without creating a dependency cycle — they depend on
//! `vord-profiles` for `RuleId`/`Severity`, not the other way around. So
//! the rule ids and severities below are literals, cross-checked by hand
//! against each rule's real `RuleId::new(...)` and `default_severity()` in
//! its source file (`rulesets/*/src/*.rs`) at the time this was written —
//! never invented. Each rule is commented with which ruleset it comes from
//! so a future audit can re-verify the list against the catalog.
//!
//! Curation follows each rule's own `Rule::applies_to` scoping (also
//! cross-checked by hand): a language's set only includes rules that would
//! actually fire on that language. Language identifiers are plain strings
//! here (not `vord_ast::LanguageIdentifier`) to keep this crate
//! dependency-free — pass `LanguageIdentifier::as_str()` at the call site.
//!
//! `default_profile_for_language` gives the per-language profile (Rust,
//! TypeScript/JavaScript and Python are curated in full detail per the
//! issue; every other language `LanguageIdentifier` supports gets at least
//! the language-agnostic baseline plus whatever language-specific rules
//! exist for it). `default_profile` is the combined profile across every
//! supported language — what a polyglot repo's analyzer run actually uses
//! when no project-specific profile is configured, since a single scan
//! sees many languages at once and rules already self-filter per file via
//! `applies_to`.

use std::collections::HashMap;

use crate::{QualityProfile, RuleId, Severity};

/// The built-in profile's name.
pub const DEFAULT_PROFILE_NAME: &str = "vord way";

fn rule(raw: &str) -> RuleId {
    RuleId::new(raw).expect("builtin rule id is valid namespace:code")
}

/// Rules with no language-specific behavior (`applies_to` returns `true`
/// for every language, or the rule is a whole-program cross-file rule run
/// once per scan regardless of language): secrets detection, generic OWASP
/// checks, and generic maintainability smells. Baseline for every
/// language's vord way profile.
fn generic_activations() -> Vec<(RuleId, Severity)> {
    vec![
        // rulesets/architecture — functional-paradigm analogue of god-class
        // (fires on classless TS/JS/Python/Go/Rust modules).
        (rule("architecture:functional-module"), Severity::Major),
        // rulesets/secrets — provider-pattern rules, all Severity::Blocker.
        (rule("secrets:high-entropy-string"), Severity::Major),
        (rule("secrets:aws-access-key-id"), Severity::Blocker),
        (rule("secrets:aws-secret-access-key"), Severity::Blocker),
        (rule("secrets:gcp-api-key"), Severity::Blocker),
        (rule("secrets:gcp-service-account-key"), Severity::Blocker),
        (
            rule("secrets:azure-storage-connection-string"),
            Severity::Blocker,
        ),
        (rule("secrets:azure-sas-token"), Severity::Blocker),
        (rule("secrets:stripe-live-key"), Severity::Blocker),
        (rule("secrets:private-key-block"), Severity::Blocker),
        (rule("secrets:github-token"), Severity::Blocker),
        (rule("secrets:slack-token"), Severity::Blocker),
        (rule("secrets:npm-token"), Severity::Blocker),
        (rule("secrets:jwt-like-token"), Severity::Blocker),
        // rulesets/owasp — applies_to true for every language.
        (rule("owasp:weak-crypto"), Severity::Critical),
        (rule("owasp:hardcoded-secret"), Severity::Blocker),
        (rule("owasp:command-execution"), Severity::Major),
        // rulesets/owasp — cross-file rule, runs once per scan.
        (rule("owasp:cross-file-injection"), Severity::Blocker),
        (rule("smells:ck-oo-metrics"), Severity::Major),
        (rule("smells:maintainability-index"), Severity::Major),
        (rule("ddd:repository-per-entity"), Severity::Major),
        (rule("architecture:cross-slice-coupling"), Severity::Major),
        // rulesets/architecture — cross-file rule, runs once per scan.
        (rule("architecture:dependency-cycle"), Severity::Major),
        // rulesets/architecture — cross-file, config-driven, only ever
        // registered (bin/cli::scan_with_project_config) when `vord.toml`
        // declares `[architecture]` boundaries; listed here so it's active
        // whenever it is registered, same as every other built-in rule.
        (rule("architecture:boundary-violation"), Severity::Major),
        // rulesets/architecture — zero-config hexagonal/component rules,
        // cross-file, run once per scan. They read the layering vocabulary
        // off path topology (`vord_import_graph::layer_of`) and stay silent
        // on a project whose paths name no layer at all.
        (
            rule("architecture:hexagonal-layer-violation"),
            Severity::Major,
        ),
        (
            rule("architecture:main-sequence-deviation"),
            Severity::Major,
        ),
        (
            rule("architecture:stable-dependency-violation"),
            Severity::Major,
        ),
        // rulesets/code-smells — applies_to true for every language.
        (rule("smells:todo-comment"), Severity::Info),
        (rule("smells:long-function"), Severity::Minor),
        (rule("smells:high-complexity"), Severity::Major),
        (rule("smells:cognitive-complexity"), Severity::Major),
        (rule("smells:commented-out-code"), Severity::Minor),
        (rule("smells:select-star"), Severity::Minor),
        (rule("smells:db-call-in-loop"), Severity::Major),
    ]
}

/// `owasp:permissive-cors` applies to every language except Rust
/// (`rulesets/owasp/src/permissive_cors.rs`'s `applies_to` is
/// `*lang != LanguageIdentifier::rust()`) — every curated set below adds
/// it except Rust's.
fn permissive_cors() -> (RuleId, Severity) {
    (rule("owasp:permissive-cors"), Severity::Major)
}

fn rust_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.extend([
        // rulesets/rust
        (rule("rust:mem-forget"), Severity::Major),
        (rule("rust:mem-transmute"), Severity::Critical),
        (rule("rust:process-exit"), Severity::Minor),
        (rule("rust:unsafe-undocumented"), Severity::Major),
        (rule("rust:static-mut"), Severity::Major),
        (rule("rust:mem-uninit-or-zeroed"), Severity::Critical),
        (rule("rust:box-leak"), Severity::Major),
        (rule("rust:unsafe-send-sync-impl"), Severity::Critical),
        (rule("rust:panic-in-drop"), Severity::Critical),
        (rule("rust:from-over-into"), Severity::Minor),
        (rule("rust:dbg-macro"), Severity::Minor),
        (rule("rust:drop-on-reference"), Severity::Major),
        (rule("rust:self-comparison"), Severity::Major),
        (rule("rust:float-literal-eq"), Severity::Major),
        (rule("rust:derive-hash-manual-partial-eq"), Severity::Major),
        (rule("rust:blocking-sleep-in-async"), Severity::Major),
        (rule("rust:modulo-one"), Severity::Major),
        (rule("rust:almost-swapped"), Severity::Critical),
        (rule("rust:absurd-extreme-comparison"), Severity::Major),
        (rule("rust:mutex-atomic-candidate"), Severity::Minor),
        (rule("rust:suspicious-arithmetic-impl"), Severity::Major),
        (rule("rust:lock-held-across-await"), Severity::Critical),
        (rule("rust:disallow-panic-macros"), Severity::Major),
        // rulesets/code-smells — applies_to rust only.
        (rule("smells:unwrap-usage"), Severity::Major),
        // rulesets/code-smells — applies_to typescript/python/rust.
        (rule("smells:god-class"), Severity::Major),
        (rule("smells:low-cohesion"), Severity::Major),
        // rulesets/code-smells — applies_to typescript/rust (interface/trait).
        (rule("smells:fat-interface"), Severity::Minor),
        // rulesets/architecture — per-file hexagonal purity check.
        (rule("architecture:framework-in-domain"), Severity::Major),
        // rulesets/code-smells — SOLID rules applying to typescript/python/rust.
        (rule("smells:type-check-chain"), Severity::Major),
        (rule("smells:constructor-over-injection"), Severity::Major),
        (rule("smells:service-locator"), Severity::Major),
        (rule("smells:class-fan-out"), Severity::Major),
        // rulesets/ddd — tactical DDD rules, domain-layer scoped.
        (rule("ddd:persistence-in-domain"), Severity::Minor),
        (rule("ddd:anemic-domain-model"), Severity::Major),
        (rule("ddd:public-entity-setter"), Severity::Major),
        (rule("ddd:primitive-obsession"), Severity::Minor),
        (
            rule("ddd:aggregate-exposes-internal-collection"),
            Severity::Major,
        ),
    ]);
    activations
}

/// TypeScript/JavaScript/JSX (this analyzer parses JS and JSX through the
/// TypeScript grammar — see `rulesets/react`'s module docs).
fn typescript_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.extend([
        // rulesets/owasp — applies_to typescript.
        (rule("owasp:xss"), Severity::Blocker),
        (rule("owasp:eval-usage"), Severity::Critical),
        (rule("owasp:injection"), Severity::Blocker),
        (rule("owasp:disabled-cert-validation"), Severity::Critical),
        (rule("owasp:ssrf"), Severity::Blocker),
        // rulesets/react — all applies_to typescript.
        (rule("react:rules-of-hooks-naming"), Severity::Major),
        (rule("react:rules-of-hooks-conditional"), Severity::Critical),
        (rule("react:hook-missing-deps-array"), Severity::Major),
        (rule("react:direct-state-mutation"), Severity::Critical),
        (rule("react:array-index-key"), Severity::Major),
        (rule("react:missing-list-key"), Severity::Major),
        (rule("react:dangerously-set-inner-html"), Severity::Critical),
        (rule("react:unsafe-target-blank"), Severity::Major),
        (rule("react:jsx-img-missing-alt"), Severity::Major),
        (
            rule("react:inline-prop-function-in-component"),
            Severity::Minor,
        ),
        (rule("react:exhaustive-deps"), Severity::Major),
        (rule("react:unused-state"), Severity::Minor),
        (
            rule("react:no-static-element-interactions"),
            Severity::Major,
        ),
        // rulesets/code-smells — applies_to typescript/python/rust or
        // typescript/python.
        (rule("smells:god-class"), Severity::Major),
        (rule("smells:feature-envy"), Severity::Minor),
        (rule("smells:refused-bequest"), Severity::Minor),
        (rule("smells:low-cohesion"), Severity::Major),
        (rule("smells:liskov-not-implemented"), Severity::Major),
        (rule("smells:concrete-dependency"), Severity::Major),
        (rule("smells:open-closed-violation"), Severity::Major),
        // rulesets/code-smells — applies_to typescript/rust (interface/trait).
        (rule("smells:fat-interface"), Severity::Minor),
        // rulesets/reactive — applies_to typescript (RxJS).
        (rule("reactive:missing-unsubscribe"), Severity::Major),
        (rule("reactive:subject-never-completed"), Severity::Minor),
        // rulesets/typescript — all applies_to typescript only.
        (rule("typescript:loose-equality"), Severity::Minor),
        (rule("typescript:var-declaration"), Severity::Minor),
        (rule("typescript:leftover-debug-statement"), Severity::Minor),
        (
            rule("typescript:promise-then-without-catch"),
            Severity::Major,
        ),
        (rule("typescript:math-random-for-token"), Severity::Critical),
        (rule("typescript:dynamic-regexp-source"), Severity::Major),
        (rule("typescript:redos-nested-quantifier"), Severity::Major),
        (rule("typescript:json-parse-unguarded"), Severity::Major),
        (
            rule("typescript:open-redirect-location-assignment"),
            Severity::Critical,
        ),
        (
            rule("typescript:sensitive-data-in-web-storage"),
            Severity::Critical,
        ),
        (
            rule("typescript:mass-assignment-from-request-body"),
            Severity::Critical,
        ),
        (rule("typescript:innerhtml-assignment"), Severity::Critical),
        (rule("typescript:swallowed-exception"), Severity::Major),
        (
            rule("typescript:prefer-globalthis-over-window"),
            Severity::Minor,
        ),
        (rule("typescript:prefer-replaceall"), Severity::Minor),
        (rule("typescript:sort-without-compare"), Severity::Major),
        (
            rule("typescript:prefer-default-parameters"),
            Severity::Minor,
        ),
        (
            rule("typescript:negated-ternary-condition"),
            Severity::Minor,
        ),
        (rule("typescript:redundant-type-alias"), Severity::Minor),
        (rule("typescript:constant-return-value"), Severity::Major),
        (rule("typescript:nested-ternary"), Severity::Major),
        (
            rule("typescript:max-function-nesting-depth"),
            Severity::Major,
        ),
        (rule("typescript:prefer-array-at"), Severity::Minor),
        (rule("typescript:prefer-regexp-exec"), Severity::Minor),
        (
            rule("typescript:redundant-type-assertion"),
            Severity::Minor,
        ),
        // rulesets/ai-agent — applies_to typescript/python.
        (rule("ai:llm-output-injection"), Severity::Blocker),
        // rulesets/architecture — per-file hexagonal purity check.
        (rule("architecture:framework-in-domain"), Severity::Major),
        // rulesets/code-smells — SOLID rules applying to typescript/python/rust.
        (rule("smells:type-check-chain"), Severity::Major),
        (rule("smells:constructor-over-injection"), Severity::Major),
        (rule("smells:service-locator"), Severity::Major),
        (rule("smells:class-fan-out"), Severity::Major),
        // rulesets/ddd — tactical DDD rules, domain-layer scoped.
        (rule("ddd:persistence-in-domain"), Severity::Minor),
        (rule("ddd:anemic-domain-model"), Severity::Major),
        (rule("ddd:public-entity-setter"), Severity::Major),
        (rule("ddd:primitive-obsession"), Severity::Minor),
        (
            rule("ddd:aggregate-exposes-internal-collection"),
            Severity::Major,
        ),
        // rulesets/code-smells — inheritance rules; no Rust equivalent
        // (structs have no inheritance, so `ClassRegistry` records no
        // superclass for one).
        (rule("smells:deep-inheritance"), Severity::Major),
        (rule("smells:override-narrows-contract"), Severity::Major),
    ]);
    activations
}

fn python_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.extend([
        // rulesets/owasp — applies_to python.
        (rule("owasp:eval-usage"), Severity::Critical),
        (rule("owasp:disabled-cert-validation"), Severity::Critical),
        (rule("owasp:insecure-deserialization"), Severity::Critical),
        // rulesets/code-smells — applies_to typescript/python/rust or
        // typescript/python.
        (rule("smells:god-class"), Severity::Major),
        (rule("smells:feature-envy"), Severity::Minor),
        (rule("smells:refused-bequest"), Severity::Minor),
        (rule("smells:low-cohesion"), Severity::Major),
        (rule("smells:liskov-not-implemented"), Severity::Major),
        (rule("smells:concrete-dependency"), Severity::Major),
        (rule("smells:open-closed-violation"), Severity::Major),
        // rulesets/python — all applies_to python only.
        (rule("python:mutable-default-argument"), Severity::Major),
        (rule("python:bare-except"), Severity::Major),
        (rule("python:broad-exception-swallowed"), Severity::Major),
        (rule("python:assert-used-in-production"), Severity::Minor),
        (rule("python:subprocess-shell-true"), Severity::Critical),
        (rule("python:unsafe-yaml-load"), Severity::Critical),
        (rule("python:xml-xxe-hotspot"), Severity::Major),
        (rule("python:insecure-tempfile"), Severity::Major),
        (rule("python:wildcard-import"), Severity::Minor),
        (rule("python:type-comparison"), Severity::Minor),
        (rule("python:global-statement-usage"), Severity::Minor),
        (rule("python:eager-logging-interpolation"), Severity::Minor),
        (
            rule("python:none-comparison-with-equality"),
            Severity::Minor,
        ),
        (
            rule("python:bool-comparison-with-equality"),
            Severity::Minor,
        ),
        (rule("python:literal-identity-comparison"), Severity::Major),
        (rule("python:len-as-condition"), Severity::Minor),
        (rule("python:requests-missing-timeout"), Severity::Major),
        (rule("python:flask-debug-true"), Severity::Blocker),
        (rule("python:bind-all-interfaces"), Severity::Minor),
        (
            rule("python:sql-injection-string-building"),
            Severity::Blocker,
        ),
        (rule("python:debugger-left-in-code"), Severity::Major),
        (rule("python:open-without-encoding"), Severity::Minor),
        (rule("python:unclosed-open-file"), Severity::Major),
        (rule("python:datetime-utcnow-naive"), Severity::Minor),
        (rule("python:mutable-class-attribute"), Severity::Major),
        (
            rule("python:nested-comprehension-too-deep"),
            Severity::Minor,
        ),
        (rule("python:raise-generic-exception"), Severity::Minor),
        (rule("python:raise-without-from-in-except"), Severity::Minor),
        (rule("python:unused-loop-variable"), Severity::Minor),
        // rulesets/ai-agent — applies_to typescript/python.
        (rule("ai:llm-output-injection"), Severity::Blocker),
        // rulesets/architecture — per-file hexagonal purity check.
        (rule("architecture:framework-in-domain"), Severity::Major),
        // rulesets/code-smells — SOLID rules applying to typescript/python/rust.
        (rule("smells:type-check-chain"), Severity::Major),
        (rule("smells:constructor-over-injection"), Severity::Major),
        (rule("smells:service-locator"), Severity::Major),
        (rule("smells:class-fan-out"), Severity::Major),
        // rulesets/ddd — tactical DDD rules, domain-layer scoped.
        (rule("ddd:persistence-in-domain"), Severity::Minor),
        (rule("ddd:anemic-domain-model"), Severity::Major),
        (rule("ddd:public-entity-setter"), Severity::Major),
        (rule("ddd:primitive-obsession"), Severity::Minor),
        (
            rule("ddd:aggregate-exposes-internal-collection"),
            Severity::Major,
        ),
        // rulesets/code-smells — inheritance rules; no Rust equivalent
        // (structs have no inheritance, so `ClassRegistry` records no
        // superclass for one).
        (rule("smells:deep-inheritance"), Severity::Major),
        (rule("smells:override-narrows-contract"), Severity::Major),
    ]);
    activations
}

fn php_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.extend([
        // rulesets/owasp — applies_to php (in addition to python/java/ruby).
        (rule("owasp:insecure-deserialization"), Severity::Critical),
        // rulesets/php — all applies_to php only.
        (rule("php:eval-usage"), Severity::Critical),
        (rule("php:extract-usage"), Severity::Critical),
        (rule("php:error-suppression-operator"), Severity::Minor),
        (rule("php:loose-hash-comparison"), Severity::Critical),
        (rule("php:command-execution"), Severity::Major),
        (rule("php:sql-injection-concat"), Severity::Blocker),
        (
            rule("php:dynamic-function-call-from-superglobal"),
            Severity::Blocker,
        ),
        (rule("php:variable-variable"), Severity::Major),
        (rule("php:weak-random-token"), Severity::Critical),
        (rule("php:swallowed-exception"), Severity::Major),
        // rulesets/wordpress — WPCS-shaped checks, applies_to php only.
        (
            rule("wordpress:unescaped-superglobal-output"),
            Severity::Blocker,
        ),
        (
            rule("wordpress:unsanitized-superglobal-input"),
            Severity::Major,
        ),
        (
            rule("wordpress:nonce-verification-missing"),
            Severity::Major,
        ),
        (rule("wordpress:unprepared-wpdb-query"), Severity::Blocker),
        (rule("wordpress:i18n-missing-text-domain"), Severity::Minor),
        (rule("wordpress:discouraged-function"), Severity::Major),
        (rule("wordpress:global-variable-override"), Severity::Major),
        (rule("wordpress:unsafe-plugin-menu-slug"), Severity::Major),
        (
            rule("wordpress:unversioned-enqueued-resource"),
            Severity::Minor,
        ),
        (rule("wordpress:discouraged-constant"), Severity::Minor),
        (rule("wordpress:assignment-in-condition"), Severity::Major),
    ]);
    activations
}

fn go_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.push((rule("owasp:disabled-cert-validation"), Severity::Critical));
    activations.extend([
        // rulesets/go — all applies_to go only.
        (rule("go:sql-injection-concat"), Severity::Blocker),
        (rule("go:weak-random-token"), Severity::Critical),
        (rule("go:context-value-string-key"), Severity::Major),
        (rule("go:unchecked-type-assertion"), Severity::Major),
        (rule("go:defer-in-loop"), Severity::Major),
        (rule("go:goroutine-loop-var-capture"), Severity::Major),
        // rulesets/architecture — per-file hexagonal purity check.
        (rule("architecture:framework-in-domain"), Severity::Major),
        // rulesets/code-smells — SOLID rules; Go joins these via its struct +
        // receiver-method model in `core/symbols` (`New<Type>` counts as the
        // constructor) and its `interface` declarations.
        (rule("smells:type-check-chain"), Severity::Major),
        (rule("smells:constructor-over-injection"), Severity::Major),
        (rule("smells:service-locator"), Severity::Major),
        (rule("smells:class-fan-out"), Severity::Major),
        (rule("smells:god-class"), Severity::Major),
        (rule("smells:low-cohesion"), Severity::Major),
        (rule("smells:fat-interface"), Severity::Minor),
        // rulesets/ddd — tactical DDD rules, domain-layer scoped.
        (rule("ddd:persistence-in-domain"), Severity::Minor),
        (rule("ddd:anemic-domain-model"), Severity::Major),
        (rule("ddd:public-entity-setter"), Severity::Major),
        (rule("ddd:primitive-obsession"), Severity::Minor),
        (
            rule("ddd:aggregate-exposes-internal-collection"),
            Severity::Major,
        ),
    ]);
    activations
}

fn java_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.push((rule("owasp:insecure-deserialization"), Severity::Critical));
    activations.push((rule("owasp:xss-java"), Severity::Blocker));
    activations.push((rule("owasp:path-traversal-java"), Severity::Blocker));
    activations
}

fn ruby_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.push((rule("owasp:insecure-deserialization"), Severity::Critical));
    activations
}

fn dockerfile_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.push((rule("owasp:dockerfile-root-user"), Severity::Critical));
    activations
}

fn html_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.extend([
        // rulesets/a11y — applies_to html.
        (rule("a11y:missing-lang-attribute"), Severity::Minor),
        (rule("a11y:img-missing-alt"), Severity::Major),
    ]);
    activations
}

/// Terraform/HCL, plus YAML and JSON when used for Kubernetes/CloudFormation
/// manifests — `rulesets/iac`'s two rules apply to all three
/// (`rulesets/iac/src/{open_ingress_cidr,iam_wildcard}.rs`).
fn iac_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations.extend([
        (rule("iac:open-ingress-cidr"), Severity::Critical),
        (rule("iac:iam-wildcard-permission"), Severity::Major),
    ]);
    activations
}

/// Every other `LanguageIdentifier` (C, C++, PHP, C#, Kotlin, Swift, Scala,
/// CSS, XML, Bash, Groovy, Lua, Elixir): no curated language-specific
/// ruleset exists yet, so vord way falls back to the language-agnostic
/// baseline plus the one OWASP rule (`permissive-cors`) that applies to
/// every non-Rust language.
fn generic_language_activations() -> Vec<(RuleId, Severity)> {
    let mut activations = generic_activations();
    activations.push(permissive_cors());
    activations
}

/// The curated vord way activation set for one language, keyed by
/// `LanguageIdentifier::as_str()`. Unrecognized language strings still get
/// the safe generic baseline rather than an empty profile.
fn activations_for(language: &str) -> Vec<(RuleId, Severity)> {
    match language {
        "rust" => rust_activations(),
        "typescript" => typescript_activations(),
        "python" => python_activations(),
        "php" => php_activations(),
        "go" => go_activations(),
        "java" => java_activations(),
        "ruby" => ruby_activations(),
        "dockerfile" => dockerfile_activations(),
        "html" => html_activations(),
        "hcl" | "yaml" | "json" => iac_activations(),
        _ => generic_language_activations(),
    }
}

/// Every language `LanguageIdentifier` supports, used to build the
/// combined [`default_profile`] profile. Kept in sync with
/// `vord_ast::LanguageIdentifier::new`'s match arms by hand (this crate
/// can't depend on `vord-ast` — see module docs).
const ALL_LANGUAGES: &[&str] = &[
    "rust",
    "typescript",
    "python",
    "go",
    "java",
    "c",
    "cpp",
    "php",
    "dockerfile",
    "yaml",
    "json",
    "csharp",
    "ruby",
    "kotlin",
    "swift",
    "scala",
    "html",
    "css",
    "xml",
    "hcl",
    "bash",
    "groovy",
    "lua",
    "elixir",
];

/// The vord way profile curated for a single language — e.g. what a
/// project pinned to one language would use, or what a "compare my profile
/// against vord way for Python" admin view would diff against.
pub fn default_profile_for_language(language: &str) -> QualityProfile {
    QualityProfile::from_activations(
        format!("{DEFAULT_PROFILE_NAME} ({language})"),
        activations_for(language),
    )
}

/// The combined, instance-wide vord way profile: the union of every
/// supported language's curated activations. This is what a polyglot
/// repo's analyzer run uses when a project has no explicit profile
/// assignment — a single scan can see files in several languages, and each
/// rule already self-filters to the languages it applies to via
/// `Rule::applies_to`, so one combined profile is equivalent to picking the
/// right per-language one for every file.
pub fn default_profile() -> QualityProfile {
    let mut merged: HashMap<RuleId, Severity> = HashMap::new();
    for language in ALL_LANGUAGES {
        for (rule, severity) in activations_for(language) {
            merged.insert(rule, severity);
        }
    }
    QualityProfile::from_activations(DEFAULT_PROFILE_NAME, merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_name_is_stable() {
        assert_eq!(default_profile().name(), "vord way");
    }

    #[test]
    fn rust_profile_activates_rust_specific_rules_at_their_real_default_severity() {
        let profile = default_profile_for_language("rust");
        assert_eq!(
            profile.severity_of(&RuleId::new("rust:mem-transmute").unwrap()),
            Some(Severity::Critical)
        );
        assert_eq!(
            profile.severity_of(&RuleId::new("smells:unwrap-usage").unwrap()),
            Some(Severity::Major)
        );
        // Rust is the one language permissive-cors does NOT apply to.
        assert!(!profile.is_active(&RuleId::new("owasp:permissive-cors").unwrap()));
    }

    #[test]
    fn rust_profile_does_not_activate_typescript_or_react_rules() {
        let profile = default_profile_for_language("rust");
        assert!(!profile.is_active(&RuleId::new("owasp:xss").unwrap()));
        assert!(!profile.is_active(&RuleId::new("react:missing-list-key").unwrap()));
    }

    #[test]
    fn typescript_profile_activates_xss_and_react_rules() {
        let profile = default_profile_for_language("typescript");
        assert_eq!(
            profile.severity_of(&RuleId::new("owasp:xss").unwrap()),
            Some(Severity::Blocker)
        );
        assert_eq!(
            profile.severity_of(&RuleId::new("react:direct-state-mutation").unwrap()),
            Some(Severity::Critical)
        );
        assert!(profile.is_active(&RuleId::new("owasp:permissive-cors").unwrap()));
    }

    #[test]
    fn python_profile_activates_insecure_deserialization() {
        let profile = default_profile_for_language("python");
        assert_eq!(
            profile.severity_of(&RuleId::new("owasp:insecure-deserialization").unwrap()),
            Some(Severity::Critical)
        );
        assert!(!profile.is_active(&RuleId::new("react:missing-list-key").unwrap()));
    }

    #[test]
    fn every_language_activates_the_generic_baseline() {
        for language in ALL_LANGUAGES {
            let profile = default_profile_for_language(language);
            assert!(
                profile.is_active(&RuleId::new("owasp:hardcoded-secret").unwrap()),
                "{language} should activate the generic hardcoded-secret rule"
            );
            assert!(
                profile.is_active(&RuleId::new("secrets:aws-access-key-id").unwrap()),
                "{language} should activate the generic secrets baseline"
            );
        }
    }

    #[test]
    fn unrecognized_language_falls_back_to_the_generic_baseline() {
        let profile = default_profile_for_language("cobol");
        assert!(profile.is_active(&RuleId::new("owasp:hardcoded-secret").unwrap()));
        assert!(profile.is_active(&RuleId::new("owasp:permissive-cors").unwrap()));
        assert!(!profile.is_active(&RuleId::new("rust:mem-forget").unwrap()));
    }

    #[test]
    fn combined_default_profile_is_the_union_of_every_language() {
        let combined = default_profile();
        assert!(combined.is_active(&RuleId::new("rust:mem-transmute").unwrap()));
        assert!(combined.is_active(&RuleId::new("owasp:xss").unwrap()));
        assert!(combined.is_active(&RuleId::new("owasp:insecure-deserialization").unwrap()));
        assert!(combined.is_active(&RuleId::new("a11y:img-missing-alt").unwrap()));
        assert!(combined.is_active(&RuleId::new("iac:iam-wildcard-permission").unwrap()));
        // permissive-cors applies everywhere except Rust, and other
        // languages activate it, so it's present in the union too.
        assert!(combined.is_active(&RuleId::new("owasp:permissive-cors").unwrap()));
    }
}
