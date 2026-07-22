//! Pure glue between yunq's domain (`Issue`, `Severity`, `Span`) and the LSP
//! wire types (`Diagnostic`, `DiagnosticSeverity`, `Range`). Kept free of any
//! transport/runtime concerns so it is unit-testable without a live client.
//!
//! Scope (v1): each open document is analyzed on its own, through the same
//! per-file `Rule`s the CLI/server use. Cross-file rules (taint across
//! files, duplication) and quality gates need a whole-workspace or
//! whole-project view that a single `textDocument/didChange` doesn't carry;
//! they are exercised by the CLI/server today and are future connected-mode
//! work here, not silently approximated.
//!
//! Position mapping uses byte/char offsets like the rest of yunq (tree-sitter
//! columns are byte offsets, not UTF-16 code units). This matches LSP for
//! ASCII source; it under/overshoots on lines with multi-byte characters —
//! a known simplification, not a claim of full UTF-16 compliance.

use std::path::Path;

use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range, Url};
use yunq_ast::LanguageIdentifier;
use yunq_infra_memory::{InMemoryIssueStorage, InMemoryMetricsTracker};
use yunq_rules_engine::{Issue, Severity};

/// The language for a document URI, if yunq has a parser for it.
pub fn language_for(uri: &Url) -> Option<LanguageIdentifier> {
    let path = uri.path();
    let extension = Path::new(path).extension()?.to_str()?;
    LanguageIdentifier::from_extension(extension)
}

/// Runs the full default rule set against one document's current text and
/// returns LSP diagnostics, sorted by position for stable output.
pub async fn diagnose(uri: &Url, text: &str) -> Vec<Diagnostic> {
    let Some(language) = language_for(uri) else { return Vec::new() };
    let relative_path = Path::new(uri.path())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("document")
        .to_string();
    let Ok(file) = yunq_ast::SourceFile::new(relative_path, text.to_string(), language) else {
        return Vec::new();
    };

    // A fresh service per call: state doesn't need to persist between
    // keystrokes, and this avoids the in-memory storage growing unbounded
    // over a long editing session.
    let service =
        yunq_cli::default_service(InMemoryIssueStorage::new(), InMemoryMetricsTracker::new());
    let Ok(report) = service.analyze_files(std::slice::from_ref(&file)).await else {
        return Vec::new();
    };

    let mut diagnostics: Vec<Diagnostic> = report.issues().iter().map(issue_to_diagnostic).collect();
    diagnostics.sort_by_key(|d| (d.range.start.line, d.range.start.character));
    diagnostics
}

fn issue_to_diagnostic(issue: &Issue) -> Diagnostic {
    Diagnostic {
        range: span_to_range(issue.span()),
        severity: Some(severity_to_lsp(issue.severity())),
        code: Some(tower_lsp::lsp_types::NumberOrString::String(issue.rule().to_string())),
        code_description: None,
        source: Some("yunq".to_string()),
        message: issue.message().to_string(),
        related_information: None,
        tags: None,
        data: None,
    }
}

fn span_to_range(span: yunq_ast::Span) -> Range {
    // yunq spans are 1-based; LSP positions are 0-based.
    Range {
        start: Position {
            line: span.start_line.saturating_sub(1),
            character: span.start_col.saturating_sub(1),
        },
        end: Position {
            line: span.end_line.saturating_sub(1),
            character: span.end_col.saturating_sub(1),
        },
    }
}

fn severity_to_lsp(severity: Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Info => DiagnosticSeverity::HINT,
        Severity::Minor => DiagnosticSeverity::INFORMATION,
        Severity::Major => DiagnosticSeverity::WARNING,
        Severity::Critical | Severity::Blocker => DiagnosticSeverity::ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(path: &str) -> Url {
        Url::parse(&format!("file:///{path}")).unwrap()
    }

    #[tokio::test]
    async fn flags_hardcoded_secret_with_correct_position() {
        let diagnostics = diagnose(&uri("a.ts"), "const dbPassword = \"hunter2\";\n").await;
        assert_eq!(diagnostics.len(), 1);
        let d = &diagnostics[0];
        assert_eq!(d.source.as_deref(), Some("yunq"));
        assert_eq!(d.severity, Some(DiagnosticSeverity::ERROR));
        // 1-based col 20 in yunq -> 0-based character 19 in LSP.
        assert_eq!(d.range.start, Position { line: 0, character: 19 });
    }

    #[tokio::test]
    async fn clean_file_has_no_diagnostics() {
        let diagnostics = diagnose(&uri("clean.ts"), "export const x = 1;\n").await;
        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn unsupported_extension_is_silently_skipped() {
        let diagnostics = diagnose(&uri("notes.txt"), "password = \"hunter2\"\n").await;
        assert!(diagnostics.is_empty());
    }

    #[tokio::test]
    async fn diagnostics_are_sorted_by_position() {
        let code = "eval(x);\nconst secretToken = \"hunter2hunter2\";\n";
        let diagnostics = diagnose(&uri("multi.ts"), code).await;
        assert!(diagnostics.len() >= 2);
        for pair in diagnostics.windows(2) {
            assert!(
                (pair[0].range.start.line, pair[0].range.start.character)
                    <= (pair[1].range.start.line, pair[1].range.start.character)
            );
        }
    }

    #[test]
    fn severity_mapping_covers_every_variant() {
        assert_eq!(severity_to_lsp(Severity::Info), DiagnosticSeverity::HINT);
        assert_eq!(severity_to_lsp(Severity::Minor), DiagnosticSeverity::INFORMATION);
        assert_eq!(severity_to_lsp(Severity::Major), DiagnosticSeverity::WARNING);
        assert_eq!(severity_to_lsp(Severity::Critical), DiagnosticSeverity::ERROR);
        assert_eq!(severity_to_lsp(Severity::Blocker), DiagnosticSeverity::ERROR);
    }
}
