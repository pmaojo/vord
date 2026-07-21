//! Filesystem source loader: walks a directory (gitignore-aware) and
//! translates readable files in supported languages into validated
//! [`SourceFile`]s. Unsupported and non-UTF-8 files are skipped.

mod cache;

pub use cache::FileAnalysisCache;

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
            path.to_string_lossy()
        } else {
            relative.to_string_lossy()
        };
        if let Ok(source) = SourceFile::new(display.to_string(), content, language) {
            sources.push(source);
        }
    }
    sources.sort_by(|a, b| a.path().cmp(b.path()));
    Ok(sources)
}
