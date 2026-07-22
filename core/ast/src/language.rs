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
            "rust" | "typescript" | "python" | "go" | "java" | "c" | "cpp" | "php" | "dockerfile"
            | "yaml" | "json" | "csharp" | "ruby" => Ok(Self(normalized)),
            _ => Err(UnsupportedLanguageError(raw.to_string())),
        }
    }

    pub fn rust() -> Self {
        Self("rust".to_string())
    }

    pub fn typescript() -> Self {
        Self("typescript".to_string())
    }

    pub fn python() -> Self {
        Self("python".to_string())
    }

    pub fn go() -> Self {
        Self("go".to_string())
    }

    pub fn java() -> Self {
        Self("java".to_string())
    }

    pub fn c() -> Self {
        Self("c".to_string())
    }

    pub fn cpp() -> Self {
        Self("cpp".to_string())
    }

    pub fn php() -> Self {
        Self("php".to_string())
    }

    pub fn dockerfile() -> Self {
        Self("dockerfile".to_string())
    }

    pub fn yaml() -> Self {
        Self("yaml".to_string())
    }

    pub fn json() -> Self {
        Self("json".to_string())
    }

    pub fn csharp() -> Self {
        Self("csharp".to_string())
    }

    pub fn ruby() -> Self {
        Self("ruby".to_string())
    }

    /// Maps a file extension to its language, if the extension is supported.
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension.to_ascii_lowercase().as_str() {
            "rs" => Some(Self::rust()),
            "ts" | "tsx" | "js" | "jsx" => Some(Self::typescript()),
            "py" => Some(Self::python()),
            "go" => Some(Self::go()),
            "java" => Some(Self::java()),
            "c" | "h" => Some(Self::c()),
            "cpp" | "cc" | "cxx" | "hpp" | "hh" => Some(Self::cpp()),
            "php" => Some(Self::php()),
            "dockerfile" | "docker" => Some(Self::dockerfile()),
            "yaml" | "yml" => Some(Self::yaml()),
            "json" => Some(Self::json()),
            "cs" => Some(Self::csharp()),
            "rb" => Some(Self::ruby()),
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
        assert_eq!(LanguageIdentifier::from_extension("py"), Some(LanguageIdentifier::python()));
        assert_eq!(LanguageIdentifier::from_extension("go"), Some(LanguageIdentifier::go()));
        assert_eq!(LanguageIdentifier::from_extension("rb"), Some(LanguageIdentifier::ruby()));
        assert_eq!(LanguageIdentifier::from_extension("cs"), Some(LanguageIdentifier::csharp()));
        assert_eq!(LanguageIdentifier::from_extension("cobol"), None);
    }
}
