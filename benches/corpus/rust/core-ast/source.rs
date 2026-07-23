use std::sync::Arc;

use crate::LanguageIdentifier;

/// A source file admitted into an analysis: a validated relative path, its
/// content and the language it must be parsed as.
///
/// Content is held in an `Arc<str>` so parsers can build zero-copy ASTs that
/// share the file buffer instead of duplicating text per node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    path: String,
    content: Arc<str>,
    language: LanguageIdentifier,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceFileError {
    #[error("source path must be a non-empty relative path, got {0:?}")]
    InvalidPath(String),
}

impl SourceFile {
    pub fn new(
        path: impl Into<String>,
        content: impl Into<Arc<str>>,
        language: LanguageIdentifier,
    ) -> Result<Self, SourceFileError> {
        let path = path.into();
        if path.is_empty() || path.starts_with('/') {
            return Err(SourceFileError::InvalidPath(path));
        }
        Ok(Self { path, content: content.into(), language })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    /// The shared content buffer, for building zero-copy ASTs.
    pub fn content_shared(&self) -> Arc<str> {
        Arc::clone(&self.content)
    }

    pub fn language(&self) -> &LanguageIdentifier {
        &self.language
    }

    pub fn line_count(&self) -> usize {
        self.content.lines().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absolute_and_empty_paths() {
        assert!(SourceFile::new("/etc/passwd", "", LanguageIdentifier::rust()).is_err());
        assert!(SourceFile::new("", "", LanguageIdentifier::rust()).is_err());
    }

    #[test]
    fn counts_lines() {
        let file = SourceFile::new("a.rs", "fn main() {}\nlet x = 1;\n", LanguageIdentifier::rust())
            .unwrap();
        assert_eq!(file.line_count(), 2);
    }
}
