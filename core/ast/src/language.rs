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
            | "yaml" | "json" | "csharp" | "ruby" | "kotlin" | "swift" | "scala" | "html"
            | "css" | "xml" | "hcl" | "bash" | "groovy" | "lua" | "elixir" => Ok(Self(normalized)),
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

    pub fn kotlin() -> Self {
        Self("kotlin".to_string())
    }

    pub fn swift() -> Self {
        Self("swift".to_string())
    }

    pub fn scala() -> Self {
        Self("scala".to_string())
    }

    pub fn html() -> Self {
        Self("html".to_string())
    }

    pub fn css() -> Self {
        Self("css".to_string())
    }

    pub fn xml() -> Self {
        Self("xml".to_string())
    }

    pub fn hcl() -> Self {
        Self("hcl".to_string())
    }

    pub fn bash() -> Self {
        Self("bash".to_string())
    }

    pub fn groovy() -> Self {
        Self("groovy".to_string())
    }

    pub fn lua() -> Self {
        Self("lua".to_string())
    }

    pub fn elixir() -> Self {
        Self("elixir".to_string())
    }

    /// Maps a file extension to its language, if the extension is supported.
    pub fn from_extension(extension: &str) -> Option<Self> {
        type LanguageCtor = fn() -> LanguageIdentifier;
        const EXTENSION_TABLE: &[(&str, LanguageCtor)] = &[
            ("rs", LanguageIdentifier::rust),
            ("ts", LanguageIdentifier::typescript),
            ("tsx", LanguageIdentifier::typescript),
            ("js", LanguageIdentifier::typescript),
            ("jsx", LanguageIdentifier::typescript),
            ("py", LanguageIdentifier::python),
            ("go", LanguageIdentifier::go),
            ("java", LanguageIdentifier::java),
            ("c", LanguageIdentifier::c),
            ("h", LanguageIdentifier::c),
            ("cpp", LanguageIdentifier::cpp),
            ("cc", LanguageIdentifier::cpp),
            ("cxx", LanguageIdentifier::cpp),
            ("hpp", LanguageIdentifier::cpp),
            ("hh", LanguageIdentifier::cpp),
            ("php", LanguageIdentifier::php),
            ("dockerfile", LanguageIdentifier::dockerfile),
            ("docker", LanguageIdentifier::dockerfile),
            ("yaml", LanguageIdentifier::yaml),
            ("yml", LanguageIdentifier::yaml),
            ("json", LanguageIdentifier::json),
            ("cs", LanguageIdentifier::csharp),
            ("rb", LanguageIdentifier::ruby),
            ("kt", LanguageIdentifier::kotlin),
            ("kts", LanguageIdentifier::kotlin),
            ("swift", LanguageIdentifier::swift),
            ("scala", LanguageIdentifier::scala),
            ("sc", LanguageIdentifier::scala),
            ("html", LanguageIdentifier::html),
            ("htm", LanguageIdentifier::html),
            ("css", LanguageIdentifier::css),
            ("xml", LanguageIdentifier::xml),
            ("tf", LanguageIdentifier::hcl),
            ("hcl", LanguageIdentifier::hcl),
            ("sh", LanguageIdentifier::bash),
            ("bash", LanguageIdentifier::bash),
            ("groovy", LanguageIdentifier::groovy),
            ("gvy", LanguageIdentifier::groovy),
            ("gy", LanguageIdentifier::groovy),
            ("gsh", LanguageIdentifier::groovy),
            ("lua", LanguageIdentifier::lua),
            ("ex", LanguageIdentifier::elixir),
            ("exs", LanguageIdentifier::elixir),
        ];
        let normalized = extension.to_ascii_lowercase();
        EXTENSION_TABLE.iter().find(|(ext, _)| *ext == normalized).map(|(_, ctor)| ctor())
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
        assert_eq!(LanguageIdentifier::from_extension("kt"), Some(LanguageIdentifier::kotlin()));
        assert_eq!(LanguageIdentifier::from_extension("swift"), Some(LanguageIdentifier::swift()));
        assert_eq!(LanguageIdentifier::from_extension("scala"), Some(LanguageIdentifier::scala()));
        assert_eq!(LanguageIdentifier::from_extension("html"), Some(LanguageIdentifier::html()));
        assert_eq!(LanguageIdentifier::from_extension("css"), Some(LanguageIdentifier::css()));
        assert_eq!(LanguageIdentifier::from_extension("xml"), Some(LanguageIdentifier::xml()));
        assert_eq!(LanguageIdentifier::from_extension("tf"), Some(LanguageIdentifier::hcl()));
        assert_eq!(LanguageIdentifier::from_extension("sh"), Some(LanguageIdentifier::bash()));
        assert_eq!(LanguageIdentifier::from_extension("groovy"), Some(LanguageIdentifier::groovy()));
        assert_eq!(LanguageIdentifier::from_extension("lua"), Some(LanguageIdentifier::lua()));
        assert_eq!(LanguageIdentifier::from_extension("ex"), Some(LanguageIdentifier::elixir()));
        assert_eq!(LanguageIdentifier::from_extension("exs"), Some(LanguageIdentifier::elixir()));
        assert_eq!(LanguageIdentifier::from_extension("cobol"), None);
    }
}
