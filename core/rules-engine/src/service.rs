use std::collections::HashMap;

use yunq_ast::{LanguageIdentifier, SourceFile};
use yunq_profiles::QualityProfile;

use crate::domain::{AnalysisReport, Issue, Metrics};
use crate::ports::{AstParser, IssueStorage, MetricsTracker, StorageError};
use crate::rule::Rule;

/// Orchestrates one analysis run: parse each file with the registered parser
/// for its language, run every applicable active rule, persist the resulting
/// issues and metrics through the outbound ports.
///
/// Generic over its ports, so it is fully unit-testable with in-memory fakes
/// and never knows which concrete backend it talks to.
pub struct AnalyzerService<S, M>
where
    S: IssueStorage,
    M: MetricsTracker,
{
    parsers: HashMap<LanguageIdentifier, Box<dyn AstParser>>,
    rules: Vec<Box<dyn Rule>>,
    profile: QualityProfile,
    storage: S,
    metrics: M,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl<S, M> AnalyzerService<S, M>
where
    S: IssueStorage,
    M: MetricsTracker,
{
    pub fn new(profile: QualityProfile, storage: S, metrics: M) -> Self {
        Self { parsers: HashMap::new(), rules: Vec::new(), profile, storage, metrics }
    }

    pub fn register_parser(mut self, parser: Box<dyn AstParser>) -> Self {
        self.parsers.insert(parser.language(), parser);
        self
    }

    pub fn register_rule(mut self, rule: Box<dyn Rule>) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn profile(&self) -> &QualityProfile {
        &self.profile
    }

    /// Rules currently registered, e.g. to build a default all-on profile.
    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    pub async fn analyze_files(&self, files: &[SourceFile]) -> Result<AnalysisReport, AnalyzeError> {
        let mut issues: Vec<Issue> = Vec::new();
        let mut metrics = Metrics::new();

        for file in files {
            let Some(parser) = self.parsers.get(file.language()) else {
                metrics.add_skipped_file();
                continue;
            };
            let ast = match parser.parse(file) {
                Ok(ast) => ast,
                Err(_) => {
                    metrics.add_parse_failure();
                    continue;
                }
            };
            metrics.add_file(file.line_count());

            for rule in &self.rules {
                if !rule.applies_to(file.language()) || !self.profile.is_active(rule.id()) {
                    continue;
                }
                let severity =
                    self.profile.severity_of(rule.id()).unwrap_or_else(|| rule.default_severity());
                for finding in rule.check(file, &ast) {
                    metrics.count_issue(severity);
                    issues.push(Issue::new(
                        rule.id().clone(),
                        severity,
                        finding.message,
                        file.path(),
                        finding.span,
                    ));
                }
            }
        }

        self.storage.save_issues(&issues).await?;
        self.metrics.record(&metrics).await?;
        Ok(AnalysisReport::new(issues, metrics))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use yunq_ast::{AstNode, NodeKind, Span};
    use yunq_profiles::{RuleId, Severity};

    use super::*;
    use crate::ports::{MetricsTracker, ParseError};
    use crate::rule::Finding;

    struct FakeParser {
        language: LanguageIdentifier,
        fail: bool,
    }

    impl AstParser for FakeParser {
        fn language(&self) -> LanguageIdentifier {
            self.language.clone()
        }

        fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
            if self.fail {
                return Err(ParseError::Syntax {
                    file: file.path().to_string(),
                    detail: "boom".into(),
                });
            }
            Ok(AstNode::new(NodeKind::SourceUnit, Span::new(1, 1, 1, 1), file.content(), vec![]))
        }
    }

    struct AlwaysFindsRule {
        id: RuleId,
        language: LanguageIdentifier,
    }

    impl Rule for AlwaysFindsRule {
        fn id(&self) -> &RuleId {
            &self.id
        }

        fn applies_to(&self, language: &LanguageIdentifier) -> bool {
            *language == self.language
        }

        fn default_severity(&self) -> Severity {
            Severity::Minor
        }

        fn check(&self, _file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
            vec![Finding::new("found it", Span::new(1, 1, 1, 5))]
        }
    }

    #[derive(Default)]
    struct CapturingStorage {
        saved: Mutex<Vec<Issue>>,
    }

    impl IssueStorage for &CapturingStorage {
        async fn save_issues(&self, issues: &[Issue]) -> Result<(), StorageError> {
            self.saved.lock().unwrap().extend_from_slice(issues);
            Ok(())
        }
    }

    #[derive(Default)]
    struct CapturingMetrics {
        recorded: Mutex<Vec<Metrics>>,
    }

    impl MetricsTracker for &CapturingMetrics {
        async fn record(&self, metrics: &Metrics) -> Result<(), StorageError> {
            self.recorded.lock().unwrap().push(metrics.clone());
            Ok(())
        }
    }

    fn rust_file(path: &str) -> SourceFile {
        SourceFile::new(path, "fn main() {}\n", LanguageIdentifier::rust()).unwrap()
    }

    #[test]
    fn applies_profile_severity_override_and_persists() {
        let rule_id = RuleId::new("test:always").unwrap();
        let mut profile = QualityProfile::new("test");
        profile.activate(rule_id.clone(), Severity::Blocker);

        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(Box::new(FakeParser { language: LanguageIdentifier::rust(), fail: false }))
            .register_rule(Box::new(AlwaysFindsRule {
                id: rule_id.clone(),
                language: LanguageIdentifier::rust(),
            }));

        let report =
            futures::executor::block_on(service.analyze_files(&[rust_file("a.rs")])).unwrap();

        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.issues()[0].severity(), Severity::Blocker);
        assert_eq!(report.issues()[0].rule(), &rule_id);
        assert_eq!(storage.saved.lock().unwrap().len(), 1);
        assert_eq!(metrics.recorded.lock().unwrap().len(), 1);
        assert_eq!(report.metrics().files_scanned(), 1);
    }

    #[test]
    fn inactive_rules_and_foreign_languages_produce_nothing() {
        let rule_id = RuleId::new("test:always").unwrap();
        // Empty profile: the rule is registered but never activated.
        let profile = QualityProfile::new("empty");

        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(Box::new(FakeParser { language: LanguageIdentifier::rust(), fail: false }))
            .register_rule(Box::new(AlwaysFindsRule {
                id: rule_id,
                language: LanguageIdentifier::rust(),
            }));

        let report =
            futures::executor::block_on(service.analyze_files(&[rust_file("a.rs")])).unwrap();
        assert!(report.issues().is_empty());
    }

    #[test]
    fn missing_parser_skips_and_parse_failure_is_counted() {
        let profile = QualityProfile::new("empty");
        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        // Only a failing Rust parser; TypeScript has no parser at all.
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(Box::new(FakeParser { language: LanguageIdentifier::rust(), fail: true }));

        let ts_file =
            SourceFile::new("a.ts", "const x = 1;\n", LanguageIdentifier::typescript()).unwrap();
        let report = futures::executor::block_on(
            service.analyze_files(&[rust_file("a.rs"), ts_file]),
        )
        .unwrap();

        assert_eq!(report.metrics().parse_failures(), 1);
        assert_eq!(report.metrics().files_skipped(), 1);
        assert_eq!(report.metrics().files_scanned(), 0);
    }
}
