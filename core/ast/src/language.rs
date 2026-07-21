use std::fmt;

/// A validated identifier for a supported analysis language.
///
/// The private field makes the fallible constructors the only way to obtain
/// an instance, so an unsupported language can never reach the core.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LanguageIdentifier(String);

#[derive(Debug, thiserror::Error)]
#[error("unsupported language: {0}")]
pub struct UnsupportedLanguageError(String);

impl LanguageIdentifier {
    pub fn new(raw: &str) -> Result<Self, UnsupportedLanguageError> {
        let normalized = raw.to_ascii_lowercase();
        match normalized.as_str() {
            "rust" | "typescript" => Ok(Self(normalized)),
            _ => Err(UnsupportedLanguageError(raw.to_string())),
        }
    }

    pub fn rust() -> Self {
        Self("rust".to_string())
    }

    pub fn typescript() -> Self {
        Self("typescript".to_string())
    }

    /// Maps a file extension to its language, if the extension is supported.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension {
            "rs" => Some(Self::rust()),
            "ts" | "tsx" => Some(Self::typescript()),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LanguageIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_languages_case_insensitively() {
        assert_eq!(LanguageIdentifier::new("Rust").unwrap(), LanguageIdentifier::rust());
        assert_eq!(
            LanguageIdentifier::new("TYPESCRIPT").unwrap(),
            LanguageIdentifier::typescript()
        );
    }

    #[test]
    fn rejects_unsupported_language() {
        assert!(LanguageIdentifier::new("cobol").is_err());
    }

    #[test]
    fn maps_extensions() {
        assert_eq!(LanguageIdentifier::from_extension("rs"), Some(LanguageIdentifier::rust()));
        assert_eq!(
            LanguageIdentifier::from_extension("tsx"),
            Some(LanguageIdentifier::typescript())
        );
        assert_eq!(LanguageIdentifier::from_extension("py"), None);
    }
}
