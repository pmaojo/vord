use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use yunq_ast::{LanguageIdentifier, SourceFile};
use yunq_profiles::QualityProfile;

use crate::domain::{AnalysisReport, Hotspot, Issue, Metrics};
use crate::ports::{
    AnalysisCache, AstParser, CacheKey, CachedAnalysis, IssueStorage, MetricsTracker, StorageError,
};
use crate::rule::{FindingKind, Rule};

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
    cache: Option<Arc<dyn AnalysisCache>>,
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
        Self { parsers: HashMap::new(), rules: Vec::new(), profile, storage, metrics, cache: None }
    }

    /// Enables incremental analysis: per-file results are reused when
    /// neither the file nor the engine configuration changed.
    pub fn with_cache(mut self, cache: Arc<dyn AnalysisCache>) -> Self {
        self.cache = Some(cache);
        self
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
        let mut hotspots: Vec<Hotspot> = Vec::new();
        let mut metrics = Metrics::new();

        for outcome in self.analyze_all(files) {
            match outcome {
                FileOutcome::Skipped => metrics.add_skipped_file(),
                FileOutcome::ParseFailed => metrics.add_parse_failure(),
                FileOutcome::Analyzed {
                    lines,
                    debt_minutes,
                    issues: file_issues,
                    hotspots: file_hotspots,
                    from_cache,
                } => {
                    metrics.add_file(lines);
                    metrics.add_debt(debt_minutes);
                    if from_cache {
                        metrics.add_cache_hit();
                    }
                    for issue in file_issues {
                        metrics.count_issue(issue.severity());
                        issues.push(issue);
                    }
                    hotspots.extend(file_hotspots);
                }
            }
        }

        self.storage.save_issues(&issues).await?;
        self.metrics.record(&metrics).await?;
        Ok(AnalysisReport::new(issues, hotspots, metrics))
    }

    /// Runs per-file analysis across all available cores using scoped std
    /// threads with a work-stealing index — files are independent until the
    /// cross-file phases land, so this parallelism is embarrassingly safe.
    /// Results are returned in input order, keeping reports deterministic
    /// regardless of scheduling. std-only: the core takes no runtime dep.
    fn analyze_all(&self, files: &[SourceFile]) -> Vec<FileOutcome> {
        let config_hash = self.config_fingerprint();
        let workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(files.len());
        if workers <= 1 {
            return files.iter().map(|f| self.analyze_one(f, config_hash)).collect();
        }

        let next = AtomicUsize::new(0);
        let slots: Vec<Mutex<Option<FileOutcome>>> =
            files.iter().map(|_| Mutex::new(None)).collect();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(file) = files.get(index) else { break };
                        *slots[index].lock().expect("slot lock poisoned") =
                            Some(self.analyze_one(file, config_hash));
                    }
                });
            }
        });
        slots
            .into_iter()
            .map(|slot| {
                slot.into_inner().expect("slot lock poisoned").expect("every file processed")
            })
            .collect()
    }

    fn analyze_one(&self, file: &SourceFile, config_hash: u64) -> FileOutcome {
        let key = CacheKey { content_hash: Self::content_fingerprint(file), config_hash };
        if let Some(cache) = &self.cache
            && let Some(hit) = cache.get(&key)
        {
            return FileOutcome::Analyzed {
                lines: hit.lines,
                debt_minutes: hit.debt_minutes,
                issues: hit.issues,
                hotspots: hit.hotspots,
                from_cache: true,
            };
        }

        let Some(parser) = self.parsers.get(file.language()) else {
            return FileOutcome::Skipped;
        };
        let Ok(ast) = parser.parse(file) else {
            return FileOutcome::ParseFailed;
        };

        let mut issues = Vec::new();
        let mut hotspots = Vec::new();
        let mut debt_minutes = 0usize;
        for rule in &self.rules {
            if !rule.applies_to(file.language()) || !self.profile.is_active(rule.id()) {
                continue;
            }
            let severity =
                self.profile.severity_of(rule.id()).unwrap_or_else(|| rule.default_severity());
            for finding in rule.check(file, &ast) {
                match finding.kind {
                    FindingKind::Issue => {
                        debt_minutes += rule.remediation_effort_minutes() as usize;
                        issues.push(Issue::new(
                            rule.id().clone(),
                            severity,
                            finding.message,
                            file.path(),
                            finding.span,
                        ));
                    }
                    FindingKind::Hotspot => hotspots.push(Hotspot::new(
                        rule.id().clone(),
                        finding.message,
                        file.path(),
                        finding.span,
                    )),
                }
            }
        }
        let lines = file.line_count();
        if let Some(cache) = &self.cache {
            cache.put(
                key,
                CachedAnalysis {
                    lines,
                    debt_minutes,
                    issues: issues.clone(),
                    hotspots: hotspots.clone(),
                },
            );
        }
        FileOutcome::Analyzed { lines, debt_minutes, issues, hotspots, from_cache: false }
    }

    /// Covers everything that changes analysis output besides file content:
    /// registered rules and their effective severities, profile activations,
    /// the parser roster, and the engine version. Any difference produces a
    /// different key space — stale cache entries simply miss.
    fn config_fingerprint(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        env!("CARGO_PKG_VERSION").hash(&mut hasher);
        for rule in &self.rules {
            rule.id().as_str().hash(&mut hasher);
            (rule.default_severity() as u8).hash(&mut hasher);
            self.profile.is_active(rule.id()).hash(&mut hasher);
            self.profile.severity_of(rule.id()).map(|s| s as u8).hash(&mut hasher);
        }
        let mut languages: Vec<&str> = self.parsers.keys().map(|l| l.as_str()).collect();
        languages.sort_unstable();
        languages.hash(&mut hasher);
        hasher.finish()
    }

    fn content_fingerprint(file: &SourceFile) -> u64 {
        let mut hasher = DefaultHasher::new();
        file.path().hash(&mut hasher);
        file.language().as_str().hash(&mut hasher);
        file.content().hash(&mut hasher);
        hasher.finish()
    }
}

enum FileOutcome {
    Skipped,
    ParseFailed,
    Analyzed {
        lines: usize,
        debt_minutes: usize,
        issues: Vec<Issue>,
        hotspots: Vec<Hotspot>,
        from_cache: bool,
    },
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
    fn cache_hit_skips_parsing_and_reuses_issues() {
        struct CountingParser {
            calls: Arc<AtomicUsize>,
        }
        impl AstParser for CountingParser {
            fn language(&self) -> LanguageIdentifier {
                LanguageIdentifier::rust()
            }
            fn parse(&self, file: &SourceFile) -> Result<AstNode, ParseError> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(AstNode::new(NodeKind::SourceUnit, Span::new(1, 1, 1, 1), file.content(), vec![]))
            }
        }

        #[derive(Default)]
        struct MapCache {
            entries: Mutex<HashMap<CacheKey, CachedAnalysis>>,
        }
        impl AnalysisCache for MapCache {
            fn get(&self, key: &CacheKey) -> Option<CachedAnalysis> {
                self.entries.lock().unwrap().get(key).cloned()
            }
            fn put(&self, key: CacheKey, value: CachedAnalysis) {
                self.entries.lock().unwrap().insert(key, value);
            }
        }

        let rule_id = RuleId::new("test:always").unwrap();
        let mut profile = QualityProfile::new("test");
        profile.activate(rule_id.clone(), Severity::Major);

        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        let parser_calls = Arc::new(AtomicUsize::new(0));
        let parser = Box::new(CountingParser { calls: Arc::clone(&parser_calls) });
        let cache = Arc::new(MapCache::default());
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(parser)
            .register_rule(Box::new(AlwaysFindsRule {
                id: rule_id,
                language: LanguageIdentifier::rust(),
            }))
            .with_cache(cache.clone());

        let files = vec![rust_file("a.rs")];
        let first = futures::executor::block_on(service.analyze_files(&files)).unwrap();
        let second = futures::executor::block_on(service.analyze_files(&files)).unwrap();

        assert_eq!(parser_calls.load(Ordering::Relaxed), 1, "second run must not re-parse");
        assert_eq!(first.issues(), second.issues());
        assert_eq!(second.metrics().cache_hits(), 1);
        assert_eq!(first.metrics().cache_hits(), 0);

        // A changed file misses the cache.
        let changed =
            SourceFile::new("a.rs", "fn other() {}\n", LanguageIdentifier::rust()).unwrap();
        futures::executor::block_on(service.analyze_files(&[changed])).unwrap();
        assert_eq!(parser_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn parallel_analysis_keeps_input_order_deterministic() {
        let rule_id = RuleId::new("test:always").unwrap();
        let mut profile = QualityProfile::new("test");
        profile.activate(rule_id.clone(), Severity::Minor);

        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(Box::new(FakeParser { language: LanguageIdentifier::rust(), fail: false }))
            .register_rule(Box::new(AlwaysFindsRule {
                id: rule_id,
                language: LanguageIdentifier::rust(),
            }));

        let files: Vec<SourceFile> =
            (0..128).map(|i| rust_file(&format!("src/file_{i:03}.rs"))).collect();
        let report = futures::executor::block_on(service.analyze_files(&files)).unwrap();

        assert_eq!(report.issues().len(), 128);
        assert_eq!(report.metrics().files_scanned(), 128);
        let reported: Vec<&str> = report.issues().iter().map(Issue::file).collect();
        let expected: Vec<String> = (0..128).map(|i| format!("src/file_{i:03}.rs")).collect();
        assert_eq!(reported, expected.iter().map(String::as_str).collect::<Vec<_>>());
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
