//! Filesystem source loader: walks a directory (gitignore-aware) and
//! translates readable files in supported languages into validated
//! [`SourceFile`]s. Unsupported and non-UTF-8 files are skipped.

mod baseline;
mod cache;
mod cobertura;
mod config;
mod coverage;
mod diff;
mod istanbul;
mod jacoco;
mod junit;
mod lcov;
mod llvm_cov;
mod worktree;

pub use baseline::BaselineStore;
pub use cache::FileAnalysisCache;
pub use cobertura::{CoberturaError, parse_cobertura, parse_cobertura_report};
pub use config::YunqConfig;
pub use coverage::{CoverageFormat, CoverageParseError, detect_coverage_format, parse_coverage_report};
pub use diff::changed_lines_from_unified_diff;
pub use istanbul::{IstanbulError, parse_istanbul, parse_istanbul_report};
pub use jacoco::{JacocoError, parse_jacoco, parse_jacoco_report};
pub use junit::{JunitError, parse_junit};
pub use lcov::{LcovError, parse_lcov, parse_lcov_report};
pub use llvm_cov::{LlvmCovError, parse_llvm_cov, parse_llvm_cov_report};
pub use worktree::WorktreeSandbox;

use std::io::ErrorKind;
use std::path::Path;

use ignore::WalkBuilder;
use yunq_ast::{LanguageIdentifier, SourceFile};

#[derive(Debug, thiserror::Error)]
pub enum SourceLoadError {
    #[error("failed to walk {0}")]
    Walk(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn collect_sources(root: &Path) -> Result<Vec<SourceFile>, SourceLoadError> {
    let mut sources = Vec::new();
    for entry in WalkBuilder::new(root).build() {
        let entry = entry.map_err(|e| SourceLoadError::Walk(e.to_string()))?;
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(language) = path
            .extension()
            .and_then(|e| e.to_str())
            .and_then(LanguageIdentifier::from_extension)
        else {
            continue;
        };
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == ErrorKind::InvalidData => continue,
            Err(e) => return Err(e.into()),
        };
        let relative = path.strip_prefix(root).unwrap_or(path);
        let display = if relative.as_os_str().is_empty() {
            // `root` itself is a single file (not a directory): there's no
            // meaningful subpath to strip it to, so fall back to the full
            // path with any leading `/` stripped — `SourceFile::new`
            // rejects absolute paths, and silently dropping every file
            // whenever `root` is passed as an absolute file path (e.g.
            // `yunq scan /abs/path/to/file.ts`) is the bug this avoids.
            path.to_string_lossy().trim_start_matches('/').to_string()
        } else {
            relative.to_string_lossy().to_string()
        };
        if let Ok(source) = SourceFile::new(display, content, language) {
            sources.push(source);
        }
    }
    sources.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_a_single_file_given_by_absolute_path() {
        let dir = std::env::temp_dir().join(format!(
            "yunq-collect-sources-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.ts");
        std::fs::write(&file, "eval(x);\n").unwrap();

        let absolute = file.canonicalize().unwrap();
        let sources = collect_sources(&absolute).unwrap();

        assert_eq!(sources.len(), 1, "expected the single file to be scanned");
        assert!(!sources[0].path().starts_with('/'), "path must not be absolute: {}", sources[0].path());
        assert_eq!(sources[0].content(), "eval(x);\n");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn scans_a_single_file_given_by_relative_path() {
        let dir = std::env::temp_dir().join(format!(
            "yunq-collect-sources-rel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("app.ts");
        std::fs::write(&file, "eval(x);\n").unwrap();

        let sources = collect_sources(&file).unwrap();

        assert_eq!(sources.len(), 1);
        assert!(!sources[0].path().starts_with('/'));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
