use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use yunq_ast::{LanguageIdentifier, SourceFile};
use yunq_profiles::{IssueType, QualityProfile, RuleId};

use crate::domain::{AnalysisReport, FileFunctionComplexity, Hotspot, Issue, Metrics};
use crate::ports::{
    AnalysisCache, AstParser, CacheKey, CachedAnalysis, HotspotStorage, IssueScope, IssueStorage,
    MetricsTracker, StorageError,
};
use crate::rule::{CrossFileRule, FindingKind, Rule};
use yunq_ast::AstNode;

/// Orchestrates one analysis run: parse each file with the registered parser
/// for its language, run every applicable active rule, persist the resulting
/// issues and metrics through the outbound ports.
///
/// Generic over its ports, so it is fully unit-testable with in-memory fakes
/// and never knows which concrete backend it talks to.
pub struct AnalyzerService<S, M>
where
    S: IssueStorage + HotspotStorage,
    M: MetricsTracker,
{
    parsers: HashMap<LanguageIdentifier, Box<dyn AstParser>>,
    rules: Vec<Box<dyn Rule>>,
    cross_rules: Vec<Box<dyn CrossFileRule>>,
    profile: QualityProfile,
    storage: S,
    metrics: M,
    cache: Option<Arc<dyn AnalysisCache>>,
    duplication: yunq_cpd::DuplicationConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum AnalyzeError {
    #[error(transparent)]
    Storage(#[from] StorageError),
}

/// Folds per-file outcomes into the running metrics, returning the
/// combined issues/hotspots — the reduction step behind `analyze_files`'s
/// per-file phase. `classifications` is the rule-id -> (classic issue type,
/// remediation effort) table built once from the registered rules, needed
/// here because a cached/replayed `Issue` only carries its `RuleId`, not
/// the `Rule` object itself.
fn fold_outcomes(
    outcomes: Vec<FileOutcome>,
    metrics: &mut Metrics,
    classifications: &HashMap<RuleId, (IssueType, u32)>,
) -> (Vec<Issue>, Vec<Hotspot>, Vec<FileFunctionComplexity>) {
    let mut issues: Vec<Issue> = Vec::new();
    let mut hotspots: Vec<Hotspot> = Vec::new();
    let mut function_complexities: Vec<FileFunctionComplexity> = Vec::new();
    for outcome in outcomes {
        match outcome {
            FileOutcome::Skipped => metrics.add_skipped_file(),
            FileOutcome::ParseFailed => metrics.add_parse_failure(),
            FileOutcome::Analyzed {
                lines,
                debt_minutes,
                issues: file_issues,
                hotspots: file_hotspots,
                structural,
                function_complexities: file_complexities,
                from_cache,
            } => {
                metrics.add_file(lines);
                metrics.add_debt(debt_minutes);
                metrics.add_structural(structural);
                if from_cache {
                    metrics.add_cache_hit();
                }
                for issue in file_issues {
                    metrics.count_issue(issue.severity());
                    if let Some(&(issue_type, minutes)) = classifications.get(issue.rule()) {
                        metrics.record_issue_type_and_effort(
                            issue_type,
                            issue.severity(),
                            issue.rule().clone(),
                            issue.file(),
                            minutes,
                        );
                    }
                    issues.push(issue);
                }
                hotspots.extend(file_hotspots);
                function_complexities.extend(file_complexities);
            }
        }
    }
    (issues, hotspots, function_complexities)
}

impl<S, M> AnalyzerService<S, M>
where
    S: IssueStorage + HotspotStorage,
    M: MetricsTracker,
{
    pub fn new(profile: QualityProfile, storage: S, metrics: M) -> Self {
        Self {
            parsers: HashMap::new(),
            rules: Vec::new(),
            cross_rules: Vec::new(),
            profile,
            storage,
            metrics,
            cache: None,
            duplication: yunq_cpd::DuplicationConfig::default(),
        }
    }

    pub fn with_duplication_config(mut self, config: yunq_cpd::DuplicationConfig) -> Self {
        self.duplication = config;
        self
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

    pub fn register_cross_rule(mut self, rule: Box<dyn CrossFileRule>) -> Self {
        self.cross_rules.push(rule);
        self
    }

    pub fn profile(&self) -> &QualityProfile {
        &self.profile
    }

    /// Rules currently registered, e.g. to build a default all-on profile.
    pub fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }

    /// Copy-paste detection over the whole file set. Each file's registered
    /// parser (if any) supplies real per-language tokens; files with no
    /// registered parser fall back to trimmed lines.
    fn detect_duplication(&self, files: &[SourceFile]) -> yunq_cpd::DuplicationReport {
        let tokenized: Vec<yunq_cpd::TokenizedFile> = files
            .iter()
            .filter(|file| {
                self.duplication.include_test_code || !crate::is_test_only_path(file.path())
            })
            .map(|file| {
                let mut tokenized = self
                    .parsers
                    .get(file.language())
                    .map(|parser| parser.tokenize_for_duplication(file, self.duplication.normalization))
                    .unwrap_or_else(|| yunq_cpd::TokenizedSource {
                        lines: yunq_cpd::fallback_tokenize(file),
                        declaration_lines: Vec::new(),
                    });
                if !self.duplication.include_test_code {
                    // Dropping the lines rather than the whole file matters:
                    // a source file with an inline test module still has
                    // production code worth checking, and leaving the test
                    // lines in would also let a clone straddle the boundary
                    // between the two — matching the *seam* where one ends
                    // and the other begins, which is shared by every file in
                    // a language and is not duplication at all.
                    let test_ranges = crate::rust_test_module_ranges(file.content());
                    tokenized.lines.retain(|(line, _)| !crate::in_ranges(&test_ranges, *line));
                    tokenized.declaration_lines.retain(|line| !crate::in_ranges(&test_ranges, *line));
                }
                yunq_cpd::TokenizedFile {
                    path: file.path().to_string(),
                    lines: tokenized.lines,
                    declaration_lines: tokenized.declaration_lines,
                }
            })
            .collect();
        yunq_cpd::find_duplicates(&tokenized, self.duplication)
    }

    /// Cross-file rules (e.g. inter-procedural taint) need every AST at
    /// once, so the file set is re-parsed in parallel for this phase.
    /// Appends their findings straight into `issues`/`metrics`.
    fn run_cross_file_rules(&self, files: &[SourceFile], issues: &mut Vec<Issue>, metrics: &mut Metrics) {
        let active_cross: Vec<&Box<dyn CrossFileRule>> =
            self.cross_rules.iter().filter(|r| self.profile.is_active(r.id())).collect();
        if active_cross.is_empty() {
            return;
        }
        let parsed = self.parse_all(files);
        for rule in active_cross {
            let severity = self.profile.severity_of(rule.id()).unwrap_or_else(|| rule.default_severity());
            for (file_index, finding) in rule.check(&parsed) {
                let Some((file, _)) = parsed.get(file_index) else { continue };
                metrics.count_issue(severity);
                metrics.add_debt(rule.remediation_effort_minutes() as usize);
                metrics.record_issue_type_and_effort(
                    rule.issue_type(),
                    severity,
                    rule.id().clone(),
                    file.path(),
                    rule.remediation_effort_minutes(),
                );
                issues.push(Issue::new(rule.id().clone(), severity, finding.message, file.path(), finding.span));
            }
        }
    }

    /// Rule id -> (classic issue type, remediation effort minutes), built
    /// once per run from the registered rules. Used to derive Reliability/
    /// Security ratings and remediation-effort aggregation from issues
    /// after the fact, since a cached/replayed `Issue` carries only its
    /// `RuleId`, not the `Rule` trait object that knows its classification.
    fn rule_classifications(&self) -> HashMap<RuleId, (IssueType, u32)> {
        self.rules
            .iter()
            .map(|r| (r.id().clone(), (r.issue_type(), r.remediation_effort_minutes())))
            .collect()
    }

    /// Runs one analysis and persists its issues/hotspots unscoped — the
    /// path every local, one-off caller uses (CLI, LSP, remediation's
    /// verify-before-suggest loop), none of which resolve a project at all.
    /// Equivalent to `analyze_files_scoped` with `IssueScope::default()`.
    pub async fn analyze_files(&self, files: &[SourceFile]) -> Result<AnalysisReport, AnalyzeError> {
        self.analyze_files_scoped(files, IssueScope::default()).await
    }

    /// Same as [`Self::analyze_files`], but scopes the newly-persisted
    /// issues/hotspots to a project and (if already known) an analysis —
    /// used by the `yunq-worker` composition root, the only caller that
    /// resolves a project before/while running a scan.
    pub async fn analyze_files_scoped(
        &self,
        files: &[SourceFile],
        scope: IssueScope,
    ) -> Result<AnalysisReport, AnalyzeError> {
        let mut metrics = Metrics::new();
        let classifications = self.rule_classifications();
        let (mut issues, hotspots, function_complexities) =
            fold_outcomes(self.analyze_all(files), &mut metrics, &classifications);

        let duplication = self.detect_duplication(files);
        metrics.set_duplication(duplication.duplicated_lines, duplication.clone_sets.len());

        self.run_cross_file_rules(files, &mut issues, &mut metrics);

        self.storage.save_issues(&issues, scope).await?;
        self.storage.save_hotspots(&hotspots, scope).await?;
        self.metrics.record(&metrics).await?;
        let mut report = AnalysisReport::new(issues, hotspots, metrics);
        report.set_duplications(duplication);
        report.set_function_complexities(function_complexities);
        Ok(report)
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

    /// Parses every parseable file, in parallel, preserving input order.
    fn parse_all(&self, files: &[SourceFile]) -> Vec<(SourceFile, AstNode)> {
        let next = AtomicUsize::new(0);
        let slots: Vec<Mutex<Option<Option<AstNode>>>> =
            files.iter().map(|_| Mutex::new(None)).collect();
        let workers =
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(files.len().max(1));
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(file) = files.get(index) else { break };
                        let ast = self
                            .parsers
                            .get(file.language())
                            .and_then(|parser| parser.parse(file).ok());
                        *slots[index].lock().expect("slot lock poisoned") = Some(ast);
                    }
                });
            }
        });
        files
            .iter()
            .zip(slots)
            .filter_map(|(file, slot)| {
                slot.into_inner()
                    .expect("slot lock poisoned")
                    .expect("every file processed")
                    .map(|ast| (file.clone(), ast))
            })
            .collect()
    }

    /// Runs every applicable active rule against `file`/`ast`, returning
    /// its issues, hotspots, and total remediation-effort debt.
    fn run_rules_on_file(&self, file: &SourceFile, ast: &AstNode) -> (Vec<Issue>, Vec<Hotspot>, usize) {
        let mut issues = Vec::new();
        let mut hotspots = Vec::new();
        let mut debt_minutes = 0usize;
        for rule in &self.rules {
            if !rule.applies_to(file.language()) || !self.profile.is_active(rule.id()) {
                continue;
            }
            let severity =
                self.profile.severity_of(rule.id()).unwrap_or_else(|| rule.default_severity());
            for finding in rule.check(file, ast) {
                if crate::is_suppressed(file.content(), finding.span.start_line, rule.id().as_str()) {
                    continue;
                }
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
        (issues, hotspots, debt_minutes)
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
                structural: hit.structural,
                function_complexities: hit.function_complexities,
                from_cache: true,
            };
        }

        let Some(parser) = self.parsers.get(file.language()) else {
            return FileOutcome::Skipped;
        };
        let Ok(ast) = parser.parse(file) else {
            return FileOutcome::ParseFailed;
        };
        let structural = crate::structural_metrics::compute(&ast);
        let function_complexities: Vec<FileFunctionComplexity> = crate::function_complexity::compute(&ast)
            .into_iter()
            .map(|fc| FileFunctionComplexity {
                path: file.path().to_string(),
                span: fc.span,
                cyclomatic: fc.cyclomatic,
            })
            .collect();
        let (issues, hotspots, debt_minutes) = self.run_rules_on_file(file, &ast);

        let lines = file.line_count();
        if let Some(cache) = &self.cache {
            cache.put(
                key,
                CachedAnalysis {
                    lines,
                    debt_minutes,
                    issues: issues.clone(),
                    hotspots: hotspots.clone(),
                    structural,
                    function_complexities: function_complexities.clone(),
                },
            );
        }
        FileOutcome::Analyzed {
            lines,
            debt_minutes,
            issues,
            hotspots,
            structural,
            function_complexities,
            from_cache: false,
        }
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
        structural: crate::structural_metrics::StructuralCounts,
        function_complexities: Vec<FileFunctionComplexity>,
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
    use yunq_profiles::Rating;

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

    /// A rule that always finds a Blocker `Bug`, used to prove Reliability
    /// rating and remediation-effort aggregation are actually wired into
    /// `analyze_files`, not just unit-tested against `Metrics` directly.
    struct AlwaysFindsBugRule {
        id: RuleId,
        language: LanguageIdentifier,
    }

    impl Rule for AlwaysFindsBugRule {
        fn id(&self) -> &RuleId {
            &self.id
        }

        fn applies_to(&self, language: &LanguageIdentifier) -> bool {
            *language == self.language
        }

        fn default_severity(&self) -> Severity {
            Severity::Blocker
        }

        fn issue_type(&self) -> IssueType {
            IssueType::Bug
        }

        fn remediation_effort_minutes(&self) -> u32 {
            25
        }

        fn check(&self, _file: &SourceFile, _ast: &AstNode) -> Vec<Finding> {
            vec![Finding::new("null deref", Span::new(1, 1, 1, 5))]
        }
    }

    #[derive(Default)]
    struct CapturingStorage {
        saved: Mutex<Vec<Issue>>,
        saved_hotspots: Mutex<Vec<Hotspot>>,
        saved_scope: Mutex<Vec<IssueScope>>,
    }

    impl IssueStorage for &CapturingStorage {
        async fn save_issues(&self, issues: &[Issue], scope: IssueScope) -> Result<(), StorageError> {
            self.saved.lock().unwrap().extend_from_slice(issues);
            self.saved_scope.lock().unwrap().push(scope);
            Ok(())
        }
    }

    impl HotspotStorage for &CapturingStorage {
        async fn save_hotspots(
            &self,
            hotspots: &[Hotspot],
            scope: IssueScope,
        ) -> Result<(), StorageError> {
            self.saved_hotspots.lock().unwrap().extend_from_slice(hotspots);
            self.saved_scope.lock().unwrap().push(scope);
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
        // The unscoped entry point always saves with the default (empty)
        // scope, both for the issues save and the hotspots save.
        assert_eq!(
            storage.saved_scope.lock().unwrap().as_slice(),
            [IssueScope::default(), IssueScope::default()]
        );
    }

    #[test]
    fn analyze_files_scoped_threads_project_and_analysis_ids_to_storage() {
        let rule_id = RuleId::new("test:always").unwrap();
        let mut profile = QualityProfile::new("test");
        profile.activate(rule_id.clone(), Severity::Blocker);

        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(Box::new(FakeParser { language: LanguageIdentifier::rust(), fail: false }))
            .register_rule(Box::new(AlwaysFindsRule {
                id: rule_id,
                language: LanguageIdentifier::rust(),
            }));

        let scope = IssueScope { project_id: Some(7), analysis_id: Some(42) };
        futures::executor::block_on(service.analyze_files_scoped(&[rust_file("a.rs")], scope))
            .unwrap();

        // Both the issues save and the hotspots save saw the same scope.
        assert_eq!(storage.saved_scope.lock().unwrap().as_slice(), [scope, scope]);
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

    #[test]
    fn cache_hit_skips_parsing_and_reuses_issues() {
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

    #[test]
    fn reliability_rating_and_remediation_effort_are_wired_into_a_real_report() {
        let bug_rule = RuleId::new("bugs:null-deref").unwrap();
        let smell_rule = RuleId::new("smells:always").unwrap();
        let mut profile = QualityProfile::new("test");
        profile.activate(bug_rule.clone(), Severity::Blocker);
        profile.activate(smell_rule.clone(), Severity::Minor);

        let storage = CapturingStorage::default();
        let metrics = CapturingMetrics::default();
        let service = AnalyzerService::new(profile, &storage, &metrics)
            .register_parser(Box::new(FakeParser { language: LanguageIdentifier::rust(), fail: false }))
            .register_rule(Box::new(AlwaysFindsBugRule {
                id: bug_rule.clone(),
                language: LanguageIdentifier::rust(),
            }))
            .register_rule(Box::new(AlwaysFindsRule {
                id: smell_rule.clone(),
                language: LanguageIdentifier::rust(),
            }));

        let report =
            futures::executor::block_on(service.analyze_files(&[rust_file("a.rs")])).unwrap();

        // A Blocker bug drives Reliability to E; no vulnerabilities keep Security at A;
        // the plain code smell (default type, no override) touches neither.
        assert_eq!(report.reliability_rating(), Rating::E);
        assert_eq!(report.security_rating(), Rating::A);

        let effort = report.remediation_effort();
        assert_eq!(effort.by_rule[&bug_rule], 25);
        assert_eq!(effort.by_component["a.rs"], 25 + 10); // bug (25) + default smell effort (10)

        let key = |raw: &str| yunq_profiles::MetricKey::new(raw).unwrap();
        assert_eq!(report.measure(&key("reliability_rating")), Some(5.0));
        assert_eq!(report.measure(&key("security_rating")), Some(1.0));
    }
}
