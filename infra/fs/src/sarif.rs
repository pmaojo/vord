//! SARIF 2.x report import (inbound adapter): turns another analyzer's
//! findings into vord [`Issue`]s so they land in the same report, the same
//! severity counters and the same quality gate as vord's own rules.
//!
//! SARIF (OASIS "Static Analysis Results Interchange Format") is the one
//! format every mainstream analyzer already emits — ruff, ESLint, clippy,
//! gosec, bandit, semgrep, CodeQL — so a single importer buys their whole
//! rule catalogs without vord implementing a single one of those checks.
//!
//! ## What is imported, and what is dropped
//!
//! - Only `result`s whose `kind` is `fail` (the spec's default when absent).
//!   `pass`/`notApplicable`/`informational`/`open`/`review` results are not
//!   problems and are counted as skipped, not imported.
//! - Results carrying an accepted `suppression` are dropped: the emitting
//!   tool already decided they should not be shown.
//! - A result with no physical location has nothing to attach an issue to
//!   and is skipped.
//!
//! ## Severity
//!
//! `properties.security-severity` (a CVSS 0–10 score, emitted by CodeQL and
//! semgrep among others) wins when present — it is the only signal precise
//! enough to justify `Critical`/`Blocker`. Otherwise the SARIF `level`
//! maps conservatively (`error` → `Major`, not `Critical`): a linter's
//! "error" means "this tool's default failure level", not "critical for
//! this project", and ruff/ESLint emit `error` for findings as mundane as a
//! long line. Mapping those to `Critical` would drown the gate.
//!
//! ## Classification
//!
//! Imported issues are `CodeSmell` unless the rule carries a security
//! signal (a `security-severity` score, or a `security`/`cwe-*`/`owasp-*`
//! tag), in which case they are `Vulnerability`. There is deliberately no
//! `Bug` inference: SARIF has no field that distinguishes a bug from a
//! smell, and guessing would corrupt the Reliability rating.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use vord_ast::Span;
use vord_rules_engine::{ExternalIssue, Issue, IssueType, RuleId, Severity};

#[derive(Debug, thiserror::Error)]
pub enum SarifError {
    #[error("malformed SARIF JSON: {0}")]
    Malformed(String),
    #[error("unsupported SARIF version {0:?} (this importer reads SARIF 2.x)")]
    UnsupportedVersion(String),
}

/// The outcome of importing one SARIF log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SarifImport {
    /// Findings translated into vord issues, ready for
    /// [`vord_rules_engine::AnalysisReport::add_external_issues`].
    pub issues: Vec<ExternalIssue>,
    /// Every distinct emitting tool named in the log, in encounter order —
    /// what the CLI reports back so the user can see whose rules arrived.
    pub tools: Vec<String>,
    /// Results deliberately not imported (non-`fail` kind, suppressed, or
    /// location-less). Surfaced rather than silently swallowed so a wildly
    /// wrong number is visible.
    pub skipped: usize,
}

impl SarifImport {
    fn merge(&mut self, other: SarifImport) {
        self.issues.extend(other.issues);
        for tool in other.tools {
            if !self.tools.contains(&tool) {
                self.tools.push(tool);
            }
        }
        self.skipped += other.skipped;
    }
}

/// Parses a SARIF log, keeping each result's `artifactLocation` URI as the
/// issue's file path (normalized to forward slashes, percent-decoded, and
/// with any `file://` scheme stripped).
pub fn parse_sarif(content: &str) -> Result<SarifImport, SarifError> {
    parse_sarif_impl(content, None)
}

/// Like [`parse_sarif`], but re-bases absolute paths onto `root` so imported
/// issues use the same scan-root-relative paths vord's own issues do. A URI
/// that is not under `root` keeps its absolute form rather than being
/// mangled into a wrong relative path.
pub fn parse_sarif_relative_to(content: &str, root: &Path) -> Result<SarifImport, SarifError> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    parse_sarif_impl(content, Some(&root))
}

fn parse_sarif_impl(content: &str, root: Option<&Path>) -> Result<SarifImport, SarifError> {
    let log: SarifLog =
        serde_json::from_str(content).map_err(|e| SarifError::Malformed(e.to_string()))?;

    // SARIF 1.0 is a structurally different schema; refuse it rather than
    // silently importing nothing. A missing version is assumed 2.x — some
    // emitters omit it and are otherwise well-formed 2.1.0.
    if let Some(version) = &log.version
        && !version.starts_with("2.")
    {
        return Err(SarifError::UnsupportedVersion(version.clone()));
    }

    let mut import = SarifImport::default();
    for run in &log.runs {
        import.merge(import_run(run, root));
    }
    Ok(import)
}

fn import_run(run: &Run, root: Option<&Path>) -> SarifImport {
    let tool = run
        .tool
        .driver
        .name
        .clone()
        .unwrap_or_else(|| "external".to_string());
    let catalog = RuleCatalog::build(&run.tool);

    let mut import = SarifImport {
        tools: vec![tool.clone()],
        ..Default::default()
    };
    for result in &run.results {
        match import_result(result, &tool, &catalog, root) {
            Some(issue) => import.issues.push(issue),
            None => import.skipped += 1,
        }
    }
    import
}

/// Rule metadata from `tool.driver.rules` plus every `tool.extensions[].rules`
/// (GitHub's CodeQL and semgrep both put real rules in extensions), indexed
/// both by id — how `result.ruleId` refers to them — and positionally, how
/// `result.ruleIndex` does.
struct RuleCatalog<'a> {
    by_id: HashMap<&'a str, &'a ReportingDescriptor>,
    driver_by_index: &'a [ReportingDescriptor],
}

impl<'a> RuleCatalog<'a> {
    fn build(tool: &'a Tool) -> Self {
        let mut by_id = HashMap::new();
        for component in std::iter::once(&tool.driver).chain(tool.extensions.iter()) {
            for rule in &component.rules {
                if let Some(id) = rule.id.as_deref() {
                    by_id.entry(id).or_insert(rule);
                }
            }
        }
        Self {
            by_id,
            driver_by_index: &tool.driver.rules,
        }
    }

    fn lookup(&self, result: &SarifResult) -> Option<&'a ReportingDescriptor> {
        if let Some(id) = result
            .rule_id
            .as_deref()
            .or(result.rule.as_ref().and_then(|r| r.id.as_deref()))
            && let Some(rule) = self.by_id.get(id)
        {
            return Some(rule);
        }
        let index = result
            .rule_index
            .or(result.rule.as_ref().and_then(|r| r.index))?;
        self.driver_by_index.get(index)
    }
}

fn import_result(
    result: &SarifResult,
    tool: &str,
    catalog: &RuleCatalog<'_>,
    root: Option<&Path>,
) -> Option<ExternalIssue> {
    // `kind` defaults to "fail" per the spec; anything else is not a problem.
    if result.kind.as_deref().is_some_and(|kind| kind != "fail") {
        return None;
    }
    if is_suppressed(result) {
        return None;
    }

    let rule = catalog.lookup(result);
    let raw_rule_id = result
        .rule_id
        .as_deref()
        .or(result.rule.as_ref().and_then(|r| r.id.as_deref()))
        .or(rule.and_then(|r| r.id.as_deref()))
        .or(rule.and_then(|r| r.name.as_deref()))
        .unwrap_or("unknown");

    let (file, span) = physical_location(result, root)?;
    let severity = severity_of(result, rule);
    let message = message_of(result, rule, raw_rule_id);

    Some(ExternalIssue::new(
        Issue::new(rule_id(tool, raw_rule_id), severity, message, file, span),
        issue_type_of(result, rule),
    ))
}

/// A suppression with no `status` means "accepted" per the spec; only an
/// explicitly rejected one leaves the result in play.
fn is_suppressed(result: &SarifResult) -> bool {
    result
        .suppressions
        .iter()
        .any(|s| !matches!(s.status.as_deref(), Some("rejected") | Some("underReview")))
}

/// First physical location with a URI. SARIF allows several locations per
/// result (and `relatedLocations` on top); vord issues are single-span, so
/// the primary location is the one that becomes the issue.
fn physical_location(result: &SarifResult, root: Option<&Path>) -> Option<(String, Span)> {
    let physical = result
        .locations
        .iter()
        .find_map(|l| l.physical_location.as_ref())?;
    let uri = physical.artifact_location.as_ref()?.uri.as_deref()?;
    Some((normalize_uri(uri, root), span_of(physical.region.as_ref())))
}

/// SARIF regions are 1-based in both line and column — the same convention
/// as [`Span`] — so no offset is applied. A result with no region (a
/// file-level finding, common for e.g. secret scanners) lands on line 1.
fn span_of(region: Option<&Region>) -> Span {
    let Some(region) = region else {
        return Span::new(1, 1, 1, 1);
    };
    let start_line = region.start_line.unwrap_or(1).max(1);
    let start_col = region.start_column.unwrap_or(1).max(1);
    let end_line = region.end_line.unwrap_or(start_line).max(start_line);
    let end_col = region.end_column.unwrap_or(start_col).max(1);
    Span::new(start_line, start_col, end_line, end_col)
}

/// `file:///abs/path` → `/abs/path`, `%20` → ` `, backslashes → slashes,
/// and (when `root` is known) absolute paths re-based onto it so they line
/// up with the scan-relative paths vord's own issues carry.
fn normalize_uri(uri: &str, root: Option<&Path>) -> String {
    let decoded = percent_decode(uri);
    let path = strip_file_scheme(&decoded).replace('\\', "/");
    let path = path.strip_prefix("./").unwrap_or(&path);

    let rebased = root
        .filter(|_| Path::new(path).is_absolute())
        .and_then(|root| Path::new(path).strip_prefix(root).ok())
        .map(|relative| relative.to_string_lossy().replace('\\', "/"));
    rebased.unwrap_or_else(|| path.to_string())
}

/// `file://host/path` and `file:///path` both denote `/path`; a Windows
/// `file:///C:/x` denotes `C:/x`, so the extra leading slash is dropped
/// ahead of a drive letter.
fn strip_file_scheme(uri: &str) -> String {
    let Some(rest) = uri.strip_prefix("file://") else {
        return uri.to_string();
    };
    // Skip an authority component (`file://host/path`), keeping the path.
    let path = match rest.find('/') {
        Some(slash) => &rest[slash..],
        None => rest,
    };
    let bytes = path.as_bytes();
    let is_windows_drive =
        bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b':';
    if is_windows_drive {
        path[1..].to_string()
    } else {
        path.to_string()
    }
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(hi), Some(lo)) => match (hex(*hi), hex(*lo)) {
                (Some(hi), Some(lo)) => {
                    out.push(hi * 16 + lo);
                    i += 3;
                }
                // Not a valid escape — a literal '%', kept as-is.
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| raw.to_string())
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn severity_of(result: &SarifResult, rule: Option<&ReportingDescriptor>) -> Severity {
    let security_severity = result
        .properties
        .security_severity()
        .or_else(|| rule.and_then(|r| r.properties.security_severity()));
    if let Some(score) = security_severity {
        return severity_from_cvss(score);
    }

    let level = result.level.as_deref().or_else(|| {
        rule.and_then(|r| r.default_configuration.as_ref())
            .and_then(|c| c.level.as_deref())
    });
    match level {
        Some(level) => severity_from_level(level),
        // GitHub's `problem.severity` is the pre-SARIF-level fallback some
        // CodeQL packs still emit on their own.
        None => match result
            .properties
            .problem_severity
            .as_deref()
            .or_else(|| rule.and_then(|r| r.properties.problem_severity.as_deref()))
        {
            Some("error") => Severity::Major,
            Some("warning") => Severity::Minor,
            Some("recommendation") => Severity::Info,
            // The spec's default level when nothing says otherwise.
            _ => severity_from_level("warning"),
        },
    }
}

/// CVSS bands, matching the qualitative ratings in the CVSS v3.1 spec
/// (critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0, low > 0).
fn severity_from_cvss(score: f64) -> Severity {
    if score >= 9.0 {
        Severity::Blocker
    } else if score >= 7.0 {
        Severity::Critical
    } else if score >= 4.0 {
        Severity::Major
    } else if score > 0.0 {
        Severity::Minor
    } else {
        Severity::Info
    }
}

fn severity_from_level(level: &str) -> Severity {
    match level {
        "error" => Severity::Major,
        "warning" => Severity::Minor,
        "note" => Severity::Info,
        "none" => Severity::Info,
        _ => Severity::Minor,
    }
}

fn issue_type_of(result: &SarifResult, rule: Option<&ReportingDescriptor>) -> IssueType {
    let security =
        result.properties.is_security() || rule.is_some_and(|r| r.properties.is_security());
    if security {
        IssueType::Vulnerability
    } else {
        IssueType::CodeSmell
    }
}

fn message_of(
    result: &SarifResult,
    rule: Option<&ReportingDescriptor>,
    raw_rule_id: &str,
) -> String {
    result
        .message
        .as_ref()
        .and_then(|m| m.resolve(rule))
        .or_else(|| {
            rule.and_then(|r| r.short_description.as_ref())
                .and_then(|d| d.best())
        })
        .or_else(|| {
            rule.and_then(|r| r.full_description.as_ref())
                .and_then(|d| d.best())
        })
        .unwrap_or_else(|| raw_rule_id.to_string())
}

/// `namespace:code` in lowercase kebab-case, the only shape [`RuleId`]
/// accepts. The emitting tool becomes the namespace so imported rules stay
/// visibly distinct from vord's own (`ruff:e501`, `eslint:no-eval`,
/// `semgrep:python-lang-security-audit-dangerous-subprocess-use`).
fn rule_id(tool: &str, raw: &str) -> RuleId {
    let namespace = slug(tool, "external");
    let code = slug(raw, "unknown");
    RuleId::new(&format!("{namespace}:{code}"))
        .expect("slug() emits only ascii lowercase/digits/dashes, which RuleId accepts")
}

/// Lowercases and collapses every run of non-alphanumeric characters into a
/// single dash, so `E501`, `no-unused-vars`, `clippy::needless_borrow` and
/// `python.lang.security.audit.x` all become valid rule-id parts.
fn slug(raw: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending_dash = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            out.push(ch.to_ascii_lowercase());
            pending_dash = false;
        } else {
            pending_dash = true;
        }
    }
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 schema subset. Unknown fields are ignored by serde, which is
// what makes this tolerant of every emitter's extra properties.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SarifLog {
    version: Option<String>,
    #[serde(default)]
    runs: Vec<Run>,
}

#[derive(Deserialize)]
struct Run {
    #[serde(default)]
    tool: Tool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Deserialize, Default)]
struct Tool {
    #[serde(default)]
    driver: ToolComponent,
    #[serde(default)]
    extensions: Vec<ToolComponent>,
}

#[derive(Deserialize, Default)]
struct ToolComponent {
    name: Option<String>,
    #[serde(default)]
    rules: Vec<ReportingDescriptor>,
}

#[derive(Deserialize)]
struct ReportingDescriptor {
    id: Option<String>,
    name: Option<String>,
    #[serde(rename = "shortDescription")]
    short_description: Option<MultiformatMessage>,
    #[serde(rename = "fullDescription")]
    full_description: Option<MultiformatMessage>,
    #[serde(default, rename = "messageStrings")]
    message_strings: HashMap<String, MultiformatMessage>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: Option<ReportingConfiguration>,
    #[serde(default)]
    properties: Properties,
}

#[derive(Deserialize)]
struct ReportingConfiguration {
    level: Option<String>,
}

/// The `properties` bag, narrowed to the conventional keys analyzers agree
/// on: GitHub's `security-severity` (CVSS as a string, occasionally a
/// number) and `problem.severity`, plus free-form `tags`.
#[derive(Deserialize, Default)]
struct Properties {
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default, rename = "security-severity")]
    security_severity: Option<serde_json::Value>,
    #[serde(default, rename = "problem.severity")]
    problem_severity: Option<String>,
}

impl Properties {
    fn security_severity(&self) -> Option<f64> {
        match self.security_severity.as_ref()? {
            serde_json::Value::Number(n) => n.as_f64(),
            serde_json::Value::String(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    fn is_security(&self) -> bool {
        self.security_severity().is_some()
            || self.tags.iter().any(|tag| {
                let tag = tag.to_ascii_lowercase();
                tag == "security" || tag.starts_with("cwe") || tag.starts_with("owasp")
            })
    }
}

#[derive(Deserialize)]
struct MultiformatMessage {
    text: Option<String>,
    markdown: Option<String>,
}

impl MultiformatMessage {
    fn best(&self) -> Option<String> {
        self.text.clone().or_else(|| self.markdown.clone())
    }
}

#[derive(Deserialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(rename = "ruleIndex")]
    rule_index: Option<usize>,
    rule: Option<ReportingDescriptorReference>,
    kind: Option<String>,
    level: Option<String>,
    message: Option<Message>,
    #[serde(default)]
    locations: Vec<Location>,
    #[serde(default)]
    suppressions: Vec<Suppression>,
    #[serde(default)]
    properties: Properties,
}

#[derive(Deserialize)]
struct ReportingDescriptorReference {
    id: Option<String>,
    index: Option<usize>,
}

#[derive(Deserialize)]
struct Message {
    text: Option<String>,
    markdown: Option<String>,
    id: Option<String>,
    #[serde(default)]
    arguments: Vec<String>,
}

impl Message {
    /// Inline `text`/`markdown` when present, else the rule's
    /// `messageStrings[id]` template with `{0}`, `{1}`, … substituted from
    /// `arguments` — the indirection CodeQL and MSBuild-family tools use.
    fn resolve(&self, rule: Option<&ReportingDescriptor>) -> Option<String> {
        if let Some(text) = self.text.clone().or_else(|| self.markdown.clone()) {
            return Some(text);
        }
        let id = self.id.as_deref()?;
        let template = rule?.message_strings.get(id)?.best()?;
        Some(
            self.arguments
                .iter()
                .enumerate()
                .fold(template, |acc, (i, arg)| {
                    acc.replace(&format!("{{{i}}}"), arg)
                }),
        )
    }
}

#[derive(Deserialize)]
struct Location {
    #[serde(rename = "physicalLocation")]
    physical_location: Option<PhysicalLocation>,
}

#[derive(Deserialize)]
struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: Option<ArtifactLocation>,
    region: Option<Region>,
}

#[derive(Deserialize)]
struct ArtifactLocation {
    uri: Option<String>,
}

#[derive(Deserialize)]
struct Region {
    #[serde(rename = "startLine")]
    start_line: Option<u32>,
    #[serde(rename = "startColumn")]
    start_column: Option<u32>,
    #[serde(rename = "endLine")]
    end_line: Option<u32>,
    #[serde(rename = "endColumn")]
    end_column: Option<u32>,
}

#[derive(Deserialize)]
struct Suppression {
    status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but realistic ruff log: driver name, rule catalog, one
    /// result with a region.
    fn ruff_log() -> &'static str {
        r#"{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "ruff",
          "informationUri": "https://docs.astral.sh/ruff",
          "rules": [
            {
              "id": "E501",
              "shortDescription": { "text": "Line too long" },
              "defaultConfiguration": { "level": "error" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "E501",
          "level": "error",
          "message": { "text": "Line too long (105 > 88)" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/app.py" },
                "region": { "startLine": 12, "startColumn": 89, "endLine": 12, "endColumn": 106 }
              }
            }
          ]
        }
      ]
    }
  ]
}"#
    }

    #[test]
    fn imports_a_ruff_result_with_tool_namespaced_rule_id_and_span() {
        let import = parse_sarif(ruff_log()).unwrap();
        assert_eq!(import.tools, vec!["ruff".to_string()]);
        assert_eq!(import.skipped, 0);
        assert_eq!(import.issues.len(), 1);

        let imported = &import.issues[0];
        assert_eq!(imported.issue.rule().as_str(), "ruff:e501");
        assert_eq!(imported.issue.file(), "src/app.py");
        assert_eq!(imported.issue.message(), "Line too long (105 > 88)");
        assert_eq!(imported.issue.span(), Span::new(12, 89, 12, 106));
        // A linter "error" is not a project-critical finding.
        assert_eq!(imported.issue.severity(), Severity::Major);
        assert_eq!(imported.issue_type, IssueType::CodeSmell);
        // No interchange format carries effort; none is invented.
        assert_eq!(imported.remediation_effort_minutes, 0);
    }

    #[test]
    fn security_severity_overrides_level_and_marks_the_issue_a_vulnerability() {
        let log = r#"{
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "CodeQL", "rules": [{
      "id": "js/sql-injection",
      "properties": { "security-severity": "9.3", "tags": ["security", "external/cwe/cwe-089"] }
    }]}},
    "results": [{
      "ruleId": "js/sql-injection",
      "level": "warning",
      "message": { "text": "User-provided value flows to a SQL query." },
      "locations": [{ "physicalLocation": {
        "artifactLocation": { "uri": "server/db.js" },
        "region": { "startLine": 4 }
      }}]
    }]
  }]
}"#;
        let import = parse_sarif(log).unwrap();
        let imported = &import.issues[0];
        assert_eq!(imported.issue.rule().as_str(), "codeql:js-sql-injection");
        // CVSS 9.3 beats the result's own "warning" level.
        assert_eq!(imported.issue.severity(), Severity::Blocker);
        assert_eq!(imported.issue_type, IssueType::Vulnerability);
        // A region with only startLine still produces a usable span.
        assert_eq!(imported.issue.span(), Span::new(4, 1, 4, 1));
    }

    #[test]
    fn cwe_and_owasp_tags_alone_classify_a_finding_as_a_vulnerability() {
        let log = r#"{
  "runs": [{
    "tool": { "driver": { "name": "gosec", "rules": [{
      "id": "G401", "properties": { "tags": ["CWE-326"] }
    }]}},
    "results": [{
      "ruleId": "G401", "level": "error", "message": { "text": "Weak crypto primitive" },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "hash.go" } } }]
    }]
  }]
}"#;
        let imported = &parse_sarif(log).unwrap().issues[0];
        assert_eq!(imported.issue_type, IssueType::Vulnerability);
        // No CVSS score, so the level mapping still applies.
        assert_eq!(imported.issue.severity(), Severity::Major);
        // A location with no region at all lands on line 1.
        assert_eq!(imported.issue.span(), Span::new(1, 1, 1, 1));
    }

    #[test]
    fn severity_falls_back_through_level_then_rule_config_then_the_spec_default() {
        let log = r#"{
  "runs": [{
    "tool": { "driver": { "name": "t", "rules": [
      { "id": "from-config", "defaultConfiguration": { "level": "note" } },
      { "id": "no-signal" }
    ]}},
    "results": [
      { "ruleId": "from-config", "message": { "text": "m" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a" } } }] },
      { "ruleId": "no-signal", "message": { "text": "m" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "b" } } }] }
    ]
  }]
}"#;
        let issues = parse_sarif(log).unwrap().issues;
        assert_eq!(issues[0].issue.severity(), Severity::Info);
        // SARIF's default level is "warning" when nothing declares one.
        assert_eq!(issues[1].issue.severity(), Severity::Minor);
    }

    #[test]
    fn non_fail_kinds_and_accepted_suppressions_are_skipped_not_imported() {
        let log = r#"{
  "runs": [{
    "tool": { "driver": { "name": "semgrep" } },
    "results": [
      { "ruleId": "a", "kind": "pass", "message": { "text": "ok" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "x" } } }] },
      { "ruleId": "b", "kind": "notApplicable", "message": { "text": "n/a" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "x" } } }] },
      { "ruleId": "c", "message": { "text": "hushed" }, "suppressions": [{ "kind": "inSource" }],
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "x" } } }] },
      { "ruleId": "d", "message": { "text": "still open" },
        "suppressions": [{ "kind": "inSource", "status": "rejected" }],
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "x" } } }] },
      { "ruleId": "e", "kind": "fail", "message": { "text": "no location" } }
    ]
  }]
}"#;
        let import = parse_sarif(log).unwrap();
        assert_eq!(import.skipped, 4);
        assert_eq!(import.issues.len(), 1);
        // Only the explicitly *rejected* suppression survives.
        assert_eq!(import.issues[0].issue.rule().as_str(), "semgrep:d");
    }

    #[test]
    fn rules_are_resolved_by_index_and_from_tool_extensions() {
        let log = r#"{
  "runs": [{
    "tool": {
      "driver": { "name": "CodeQL", "rules": [
        { "id": "first", "shortDescription": { "text": "first rule" } },
        { "id": "second", "shortDescription": { "text": "second rule" } }
      ]},
      "extensions": [{ "name": "codeql/python-queries", "rules": [
        { "id": "py/flask-debug", "properties": { "security-severity": 7.5 } }
      ]}]
    },
    "results": [
      { "ruleIndex": 1,
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a" } } }] },
      { "ruleId": "py/flask-debug", "message": { "text": "Flask in debug mode" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "b" } } }] }
    ]
  }]
}"#;
        let issues = parse_sarif(log).unwrap().issues;
        // No message on the result: the rule's shortDescription stands in.
        assert_eq!(issues[0].issue.rule().as_str(), "codeql:second");
        assert_eq!(issues[0].issue.message(), "second rule");
        // A numeric (not string) security-severity from an extension rule.
        assert_eq!(issues[1].issue.severity(), Severity::Critical);
        assert_eq!(issues[1].issue_type, IssueType::Vulnerability);
    }

    #[test]
    fn message_ids_are_resolved_against_the_rules_message_strings() {
        let log = r#"{
  "runs": [{
    "tool": { "driver": { "name": "t", "rules": [{
      "id": "r", "messageStrings": { "default": { "text": "{0} is deprecated, use {1}" } }
    }]}},
    "results": [{
      "ruleId": "r",
      "message": { "id": "default", "arguments": ["substr", "slice"] },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a.js" } } }]
    }]
  }]
}"#;
        let issues = parse_sarif(log).unwrap().issues;
        assert_eq!(issues[0].issue.message(), "substr is deprecated, use slice");
    }

    #[test]
    fn a_result_with_no_message_anywhere_falls_back_to_the_rule_id() {
        let log = r#"{
  "runs": [{
    "tool": { "driver": { "name": "t" } },
    "results": [{ "ruleId": "some-rule",
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a" } } }] }]
  }]
}"#;
        assert_eq!(
            parse_sarif(log).unwrap().issues[0].issue.message(),
            "some-rule"
        );
    }

    #[test]
    fn several_runs_in_one_log_merge_and_their_tools_are_all_reported() {
        let log = r#"{
  "runs": [
    { "tool": { "driver": { "name": "eslint" } },
      "results": [{ "ruleId": "no-eval", "level": "error", "message": { "text": "eval" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "a.js" } } }] }] },
    { "tool": { "driver": { "name": "clippy" } },
      "results": [{ "ruleId": "clippy::needless_borrow", "level": "warning", "message": { "text": "borrow" },
        "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/lib.rs" } } }] }] }
  ]
}"#;
        let import = parse_sarif(log).unwrap();
        assert_eq!(
            import.tools,
            vec!["eslint".to_string(), "clippy".to_string()]
        );
        let ids: Vec<&str> = import
            .issues
            .iter()
            .map(|i| i.issue.rule().as_str())
            .collect();
        assert_eq!(ids, vec!["eslint:no-eval", "clippy:clippy-needless-borrow"]);
    }

    #[test]
    fn a_run_with_no_results_imports_nothing_and_is_not_an_error() {
        let log = r#"{ "version": "2.1.0", "runs": [{ "tool": { "driver": { "name": "ruff" } }, "results": [] }] }"#;
        let import = parse_sarif(log).unwrap();
        assert!(import.issues.is_empty());
        assert_eq!(import.skipped, 0);
    }

    #[test]
    fn sarif_1_0_is_rejected_rather_than_silently_importing_nothing() {
        let log = r#"{ "version": "1.0.0", "runs": [] }"#;
        assert!(matches!(parse_sarif(log), Err(SarifError::UnsupportedVersion(v)) if v == "1.0.0"));
    }

    #[test]
    fn malformed_input_is_an_error() {
        assert!(matches!(parse_sarif(""), Err(SarifError::Malformed(_))));
        assert!(matches!(
            parse_sarif("{ not json"),
            Err(SarifError::Malformed(_))
        ));
    }

    #[test]
    fn file_uris_are_decoded_and_rebased_onto_the_scan_root() {
        let root = std::env::temp_dir().join("vord-sarif-root");
        std::fs::create_dir_all(root.join("src")).unwrap();
        let root = root.canonicalize().unwrap();

        let log = format!(
            r#"{{ "runs": [{{ "tool": {{ "driver": {{ "name": "t" }} }}, "results": [
                {{ "ruleId": "r", "message": {{ "text": "m" }}, "locations": [{{ "physicalLocation": {{
                    "artifactLocation": {{ "uri": "file://{}/src/my%20file.py" }} }} }}] }},
                {{ "ruleId": "r", "message": {{ "text": "m" }}, "locations": [{{ "physicalLocation": {{
                    "artifactLocation": {{ "uri": "file:///elsewhere/other.py" }} }} }}] }}
            ] }}] }}"#,
            root.display()
        );

        let issues = parse_sarif_relative_to(&log, &root).unwrap().issues;
        assert_eq!(issues[0].issue.file(), "src/my file.py");
        // Outside the scan root: kept absolute rather than mangled.
        assert_eq!(issues[1].issue.file(), "/elsewhere/other.py");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn windows_style_uris_and_relative_prefixes_normalize_to_forward_slashes() {
        assert_eq!(
            normalize_uri("file:///C:/proj/src/main.rs", None),
            "C:/proj/src/main.rs"
        );
        assert_eq!(normalize_uri("./src/app.ts", None), "src/app.ts");
        assert_eq!(normalize_uri("src\\app.ts", None), "src/app.ts");
        assert_eq!(
            normalize_uri("file://localhost/var/tmp/a.py", None),
            "/var/tmp/a.py"
        );
    }

    #[test]
    fn slugging_produces_valid_rule_ids_from_every_tools_id_convention() {
        assert_eq!(rule_id("Ruff", "E501").as_str(), "ruff:e501");
        assert_eq!(
            rule_id("ESLint", "@typescript-eslint/no-explicit-any").as_str(),
            "eslint:typescript-eslint-no-explicit-any"
        );
        assert_eq!(
            rule_id("Bandit", "B602:subprocess_popen_with_shell_equals_true").as_str(),
            "bandit:b602-subprocess-popen-with-shell-equals-true"
        );
        // Non-ASCII and empty inputs still yield a well-formed id.
        assert_eq!(rule_id("", "").as_str(), "external:unknown");
        assert_eq!(rule_id("tool", "règle").as_str(), "tool:r-gle");
    }

    #[test]
    fn cvss_bands_cover_every_severity() {
        assert_eq!(severity_from_cvss(10.0), Severity::Blocker);
        assert_eq!(severity_from_cvss(9.0), Severity::Blocker);
        assert_eq!(severity_from_cvss(8.9), Severity::Critical);
        assert_eq!(severity_from_cvss(7.0), Severity::Critical);
        assert_eq!(severity_from_cvss(6.9), Severity::Major);
        assert_eq!(severity_from_cvss(4.0), Severity::Major);
        assert_eq!(severity_from_cvss(3.9), Severity::Minor);
        assert_eq!(severity_from_cvss(0.0), Severity::Info);
    }
}
