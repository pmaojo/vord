//! File-backed implementation of the `AnalysisCache` port: a JSON store of
//! per-file analysis results, loaded once at open and persisted explicitly.
//! Corrupt or stale files fail open (empty cache). The wire DTOs live here,
//! at the edge; entries are rebuilt through the strict domain constructors.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use yunq_ast::Span;
use yunq_rules_engine::{
    AnalysisCache, CacheKey, CachedAnalysis, Hotspot, HotspotStatus, Issue, RuleId, Severity,
    StructuralCounts,
};

#[derive(Serialize, Deserialize, Clone)]
struct CachedIssueDto {
    rule: String,
    severity: String,
    message: String,
    file: String,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
}

#[derive(Serialize, Deserialize, Clone)]
struct CachedHotspotDto {
    rule: String,
    message: String,
    file: String,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
}

#[derive(Serialize, Deserialize, Clone, Default)]
struct CachedFileDto {
    lines: usize,
    debt_minutes: usize,
    issues: Vec<CachedIssueDto>,
    hotspots: Vec<CachedHotspotDto>,
    // Added after the initial cache format shipped; entries written by
    // older yunq versions simply come back as zero (fail-open, same
    // migration pattern as `infra/fs::BaselineStore`).
    #[serde(default)]
    functions: usize,
    #[serde(default)]
    classes: usize,
    #[serde(default)]
    statements: usize,
    #[serde(default)]
    comment_lines: usize,
    #[serde(default)]
    max_nesting_depth: usize,
}

pub struct FileAnalysisCache {
    path: PathBuf,
    entries: Mutex<HashMap<String, CachedFileDto>>,
}

impl FileAnalysisCache {
    /// Opens (or initializes) a cache stored at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let entries = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        Self { path, entries: Mutex::new(entries) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Writes the current entries back to disk.
    pub fn persist(&self) -> std::io::Result<()> {
        let entries = self.entries.lock().expect("cache lock poisoned");
        let json = serde_json::to_string(&*entries)?;
        std::fs::write(&self.path, json)
    }
}

fn key_string(key: &CacheKey) -> String {
    format!("{:016x}{:016x}", key.content_hash, key.config_hash)
}

fn to_domain(dto: &CachedFileDto) -> Option<CachedAnalysis> {
    let issues = dto
        .issues
        .iter()
        .map(|issue| {
            Some(Issue::new(
                RuleId::new(&issue.rule).ok()?,
                Severity::parse(&issue.severity)?,
                issue.message.clone(),
                issue.file.clone(),
                Span::new(issue.start_line, issue.start_col, issue.end_line, issue.end_col),
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    let hotspots = dto
        .hotspots
        .iter()
        .map(|h| {
            Some(Hotspot::restore(
                RuleId::new(&h.rule).ok()?,
                h.message.clone(),
                h.file.clone(),
                Span::new(h.start_line, h.start_col, h.end_line, h.end_col),
                // Cached results are fresh detections, always to-review.
                HotspotStatus::ToReview,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    Some(CachedAnalysis {
        lines: dto.lines,
        debt_minutes: dto.debt_minutes,
        issues,
        hotspots,
        structural: StructuralCounts {
            functions: dto.functions,
            classes: dto.classes,
            statements: dto.statements,
            comment_lines: dto.comment_lines,
            max_nesting_depth: dto.max_nesting_depth,
        },
    })
}

fn to_dto(value: &CachedAnalysis) -> CachedFileDto {
    CachedFileDto {
        lines: value.lines,
        debt_minutes: value.debt_minutes,
        functions: value.structural.functions,
        classes: value.structural.classes,
        statements: value.structural.statements,
        comment_lines: value.structural.comment_lines,
        max_nesting_depth: value.structural.max_nesting_depth,
        hotspots: value
            .hotspots
            .iter()
            .map(|h| CachedHotspotDto {
                rule: h.rule().to_string(),
                message: h.message().to_string(),
                file: h.file().to_string(),
                start_line: h.span().start_line,
                start_col: h.span().start_col,
                end_line: h.span().end_line,
                end_col: h.span().end_col,
            })
            .collect(),
        issues: value
            .issues
            .iter()
            .map(|issue| CachedIssueDto {
                rule: issue.rule().to_string(),
                severity: issue.severity().to_string(),
                message: issue.message().to_string(),
                file: issue.file().to_string(),
                start_line: issue.span().start_line,
                start_col: issue.span().start_col,
                end_line: issue.span().end_line,
                end_col: issue.span().end_col,
            })
            .collect(),
    }
}

impl AnalysisCache for FileAnalysisCache {
    fn get(&self, key: &CacheKey) -> Option<CachedAnalysis> {
        let entries = self.entries.lock().expect("cache lock poisoned");
        entries.get(&key_string(key)).and_then(to_domain)
    }

    fn put(&self, key: CacheKey, value: CachedAnalysis) {
        let mut entries = self.entries.lock().expect("cache lock poisoned");
        entries.insert(key_string(&key), to_dto(&value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_disk() {
        let dir = std::env::temp_dir().join(format!("yunq-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");

        let key = CacheKey { content_hash: 0xabc, config_hash: 0xdef };
        let value = CachedAnalysis {
            lines: 7,
            debt_minutes: 10,
            structural: StructuralCounts {
                functions: 2,
                classes: 1,
                statements: 5,
                comment_lines: 3,
                max_nesting_depth: 2,
            },
            hotspots: vec![Hotspot::new(
                RuleId::new("owasp:command-execution").unwrap(),
                "review this",
                "a.ts",
                Span::new(9, 1, 9, 20),
            )],
            issues: vec![Issue::new(
                RuleId::new("owasp:eval-usage").unwrap(),
                Severity::Critical,
                "boom",
                "a.ts",
                Span::new(1, 2, 3, 4),
            )],
        };

        let cache = FileAnalysisCache::open(&path);
        assert!(cache.get(&key).is_none());
        cache.put(key, value.clone());
        cache.persist().unwrap();

        let reopened = FileAnalysisCache::open(&path);
        let hit = reopened.get(&key).expect("hit after reopen");
        assert_eq!(hit.lines, 7);
        assert_eq!(hit.debt_minutes, 10);
        assert_eq!(hit.issues.len(), 1);
        assert_eq!(hit.issues[0].message(), "boom");
        assert_eq!(hit.hotspots.len(), 1);
        assert_eq!(hit.hotspots[0].status(), HotspotStatus::ToReview);
        assert_eq!(hit.structural, value.structural);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_structural_fields_fail_open_to_zero() {
        // Simulates a cache file written by a yunq version that predates
        // structural counters: the JSON simply omits those keys.
        let dir = std::env::temp_dir()
            .join(format!("yunq-cache-legacy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cache.json");
        let key = CacheKey { content_hash: 0x1, config_hash: 0x2 };
        std::fs::write(
            &path,
            format!(
                r#"{{"{}":{{"lines":3,"debt_minutes":0,"issues":[],"hotspots":[]}}}}"#,
                key_string(&key)
            ),
        )
        .unwrap();

        let cache = FileAnalysisCache::open(&path);
        let hit = cache.get(&key).expect("legacy entry still parses");
        assert_eq!(hit.structural, StructuralCounts::default());

        std::fs::remove_dir_all(&dir).ok();
    }
}
