use yunq_ast::{AstNode, LanguageIdentifier, SourceFile};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, Severity};

declare_rule_id!(BulletproofReactFolderRule, "react:bulletproof-folder-structure");

impl Rule for BulletproofReactFolderRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, language: &LanguageIdentifier) -> bool {
        language.is_typescript() || language.is_javascript()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        let path = file.path();
        if !path.starts_with("src/") && !path.starts_with("src\\") {
            return Vec::new();
        }

        // Ignore root entry points like main.tsx, App.tsx, index.ts, vite-env.d.ts, setupTests.ts
        let file_name = path.split(['/', '\\']).next_back().unwrap_or("");
        if matches!(
            file_name,
            "index.ts"
                | "index.tsx"
                | "main.ts"
                | "main.tsx"
                | "App.tsx"
                | "App.ts"
                | "vite-env.d.ts"
                | "setupTests.ts"
                | "react-app-env.d.ts"
        ) {
            return Vec::new();
        }

        let parts: Vec<&str> = path.split(['/', '\\']).collect();
        if parts.len() <= 2 {
            // File placed directly under src/ without subfolder (e.g., src/MyButton.tsx)
            return vec![Finding::new(
                format!(
                    "Unorganized source file `{}` directly under `src/`. Place under `src/features/<feature>/` or shared directory (`src/components/`, `src/hooks/`, `src/utils/`).",
                    file_name
                ),
                ast.span(),
            )];
        }

        Vec::new()
    }
}
