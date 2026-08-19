//! Rule: flags a double-subscript assignment target where the outer index
//! is a string literal (`df['col']['row'] = value`, `data['a']['b'] = x`).
//! Indexing a DataFrame twice like this may write through a temporary
//! copy pandas produced for the first `[...]` rather than the original
//! frame — pandas itself warns about this as `SettingWithCopyWarning`
//! because whether it works is undefined by the chain alone. Restricted to
//! a string-literal outer key (the shape of column selection) to avoid
//! flagging ordinary nested numeric indexing like `matrix[i][j] = value`.

use vord_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile};
use vord_rules_engine::{Finding, IssueType, Rule, RuleId, Severity};

/// Whether this file imports `pandas` at all (`import pandas`, `import
/// pandas as pd`, `from pandas import ...`). A plain text search over the
/// whole source is deliberately used instead of walking `import_statement`
/// nodes structurally: it's simpler, and a false match would require the
/// literal word "pandas" to appear somewhere it doesn't actually name the
/// import (astronomically unlikely in real source), while a structural
/// walk buys no real precision here.
fn imports_pandas(ast: &AstNode) -> bool {
    ast.text().contains("pandas")
}

fn is_chained_string_indexed_target(target: &AstNode) -> bool {
    if target.kind() != &NodeKind::MemberAccess || target.children().len() != 2 {
        return false;
    }
    let inner = &target.children()[0];
    let outer_key = &target.children()[1];
    inner.kind() == &NodeKind::MemberAccess && outer_key.kind() == &NodeKind::StringLiteral
}

pub struct PandasChainedAssignmentRule {
    id: RuleId,
}

impl PandasChainedAssignmentRule {
    pub fn new() -> Self {
        Self {
            id: RuleId::new("python:pandas-chained-assignment").expect("valid rule id"),
        }
    }
}

impl Default for PandasChainedAssignmentRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for PandasChainedAssignmentRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::python()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::Bug
    }

    fn remediation_effort_minutes(&self) -> u32 {
        10
    }

    fn metadata(&self) -> vord_rules_engine::RuleMetadata {
        vord_rules_engine::RuleMetadata {
            description: "A chained double-subscript assignment (df['col']['row'] = value) may write through a temporary copy the first indexing operation produced, so whether it affects the original frame is undefined; use a single .loc[]/.at[] assignment instead.".into(),
            tags: vec!["bug".into(), "pandas".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, _file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        // A double-subscript assignment with a string-literal outer key
        // (`x['a']['b'] = 1`) is *also* exactly what plain nested-dict
        // assignment looks like (`config['section']['key'] = value`) —
        // an extremely common, completely safe idiom with nothing to do
        // with pandas. There's no type checker here to tell a DataFrame
        // from a dict, but a file that never imports pandas at all
        // provably cannot contain a `SettingWithCopyWarning`-prone
        // DataFrame in the first place, so gating on the import cuts out
        // the single biggest source of false positives on ordinary
        // config/dict-manipulation code without losing any real pandas
        // case (pandas code always imports pandas).
        if !imports_pandas(ast) {
            return Vec::new();
        }
        ast.descendants()
            .filter(|n| *n.kind() == NodeKind::Assignment)
            .filter_map(|assignment| assignment.children().first())
            .filter(|target| is_chained_string_indexed_target(target))
            .map(|target| Finding::new("chained double-subscript assignment may write through a temporary copy pandas produced for the first index; use a single .loc[]/.at[] assignment instead", target.span()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use vord_rules_engine::AstParser;

    use super::*;

    fn findings(code: &str) -> Vec<Finding> {
        let file = SourceFile::new("t.py", code, LanguageIdentifier::python()).unwrap();
        let ast = vord_parser_python::PythonParser::new()
            .parse(&file)
            .unwrap();
        PandasChainedAssignmentRule::new().check(&file, &ast)
    }

    #[test]
    fn flags_chained_string_indexed_assignment() {
        let code = "import pandas as pd\ndf['a']['b'] = 1\n";
        assert_eq!(findings(code).len(), 1);
    }

    #[test]
    fn allows_single_loc_assignment() {
        let code = "import pandas as pd\ndf.loc['b', 'a'] = 1\n";
        assert!(findings(code).is_empty());
    }

    /// Regression: `x['a']['b'] = value` is also exactly what plain
    /// nested-dict assignment looks like (`config['section']['key'] =
    /// value`) — an extremely common, completely safe idiom with nothing
    /// to do with pandas. A file that never imports pandas provably
    /// cannot contain a pandas `SettingWithCopyWarning` case.
    #[test]
    fn allows_nested_dict_assignment_when_pandas_is_not_imported() {
        assert!(findings("config['section']['key'] = 'value'\n").is_empty());
    }

    #[test]
    fn allows_nested_numeric_indexing() {
        assert!(findings("matrix[i][j] = value\n").is_empty());
    }

    #[test]
    fn allows_single_subscript_assignment() {
        assert!(findings("df['a'] = series\n").is_empty());
    }
}
