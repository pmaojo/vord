use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

pub struct BufferNoassertRule {
    id: RuleId,
}

impl BufferNoassertRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("typescript:buffer-noassert").expect("valid rule id"),
        }
    }
}

impl Default for BufferNoassertRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for BufferNoassertRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::typescript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Critical
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Vulnerability
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Using `noAssert` when reading or writing to a Buffer allows out-of-bounds memory access if offsets are not carefully validated.".into(),
            tags: vec!["typescript".into(), "security".into(), "memory-corruption".into(), "cwe-119".into()],
            cwe: Some(119),
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .filter(|n| {
                let Some(callee) = n.first_child() else { return false };
                if *callee.kind() != NodeKind::MemberAccess { return false; }
                let text = callee.text();
                let method = text.rsplit('.').next().unwrap_or(text);
                is_buffer_read_write_method(method)
            })
            .filter(|n| {
                crate::common::call_arguments(n).iter().any(|arg| {
                    crate::common::is_other(arg, "true") || arg.text() == "true"
                })
            })
            .map(|n| Finding::new("Using `noAssert` (passing true as the last argument to Buffer read/write methods) allows out-of-bounds memory access. Remove the argument to enable bounds checking.", n.span()))
            .collect()
    }
}

/// Node's `Buffer` instance methods that accept a `noAssert` boolean as
/// their last argument. Matched by exact method name — not a `.read`/
/// `.write` substring of the callee, which would also match unrelated
/// methods like `stream.readable()`, `fs.writeFileSync(path, data, true)`
/// or any application method merely named `*read*`/`*write*` that happens
/// to take a trailing boolean flag.
fn is_buffer_read_write_method(method: &str) -> bool {
    matches!(
        method,
        "readUInt8"
            | "readUInt16LE"
            | "readUInt16BE"
            | "readUInt32LE"
            | "readUInt32BE"
            | "readInt8"
            | "readInt16LE"
            | "readInt16BE"
            | "readInt32LE"
            | "readInt32BE"
            | "readFloatLE"
            | "readFloatBE"
            | "readDoubleLE"
            | "readDoubleBE"
            | "writeUInt8"
            | "writeUInt16LE"
            | "writeUInt16BE"
            | "writeUInt32LE"
            | "writeUInt32BE"
            | "writeInt8"
            | "writeInt16LE"
            | "writeInt16BE"
            | "writeInt32LE"
            | "writeInt32BE"
            | "writeFloatLE"
            | "writeFloatBE"
            | "writeDoubleLE"
            | "writeDoubleBE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_ast::SourceFile;
    use vord_rules_engine::AstParser;

    fn check(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.ts", code, LanguageIdentifier::typescript()).unwrap();
        let ast = vord_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        BufferNoassertRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_read_uint8_with_noassert() {
        assert_eq!(check("buf.readUInt8(0, true);\n").len(), 1);
    }

    #[test]
    fn flags_write_uint8_with_noassert() {
        assert_eq!(check("buf.writeUInt8(1, 0, true);\n").len(), 1);
    }

    #[test]
    fn allows_read_without_noassert() {
        assert!(check("buf.readUInt8(0);\n").is_empty());
    }

    #[test]
    fn allows_write_without_noassert() {
        assert!(check("buf.writeUInt8(1, 0);\n").is_empty());
    }

    #[test]
    fn allows_false_noassert() {
        assert!(check("buf.readUInt8(0, false);\n").is_empty());
    }

    #[test]
    fn ignores_unrelated_read_and_write_methods_with_a_trailing_true() {
        assert!(check("fs.writeFileSync(path, data, true);\n").is_empty());
        assert!(check("cache.write(key, value, true);\n").is_empty());
        assert!(check("logger.readValue(id, true);\n").is_empty());
        assert!(check("stream.readable(true);\n").is_empty());
    }
}
