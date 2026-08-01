//! Rules for scanning architecture graph specification files (YAML / JSON).
//!
//! Includes:
//! 1. `architecture:graph-circular-dependency`: detects node dependency loops
//!    in architecture graph `depends_on:` arrays.
//! 2. `architecture:graph-missing-contract`: detects domain nodes defined
//!    without an explicit `contract:` or `interface:` field.

use yunq_ast::{AstNode, LanguageIdentifier, NodeKind, SourceFile, Span};
use yunq_rules_engine::{declare_rule_id, Finding, IssueType, Rule, RuleId, RuleMetadata, Severity};

declare_rule_id!(
    GraphCircularDependencyRule,
    "architecture:graph-circular-dependency"
);
declare_rule_id!(
    GraphMissingContractRule,
    "architecture:graph-missing-contract"
);

#[derive(Debug, Clone, Default)]
struct ArchitectureNode {
    id: String,
    node_type: Option<String>,
    contract: Option<String>,
    interface: Option<String>,
    depends_on: Vec<String>,
    line: u32,
    line_len: u32,
}

impl ArchitectureNode {
    fn is_domain(&self) -> bool {
        if let Some(ref t) = self.node_type {
            if t.to_lowercase().contains("domain") {
                return true;
            }
        }
        self.id.to_lowercase().contains("domain")
    }

    fn has_contract_or_interface(&self) -> bool {
        let is_valid = |opt: &Option<String>| {
            if let Some(s) = opt {
                let trimmed = s.trim();
                !trimmed.is_empty() && trimmed != "null" && trimmed != "none" && trimmed != "~"
            } else {
                false
            }
        };
        is_valid(&self.contract) || is_valid(&self.interface)
    }
}

fn strip_quotes(s: &str) -> String {
    let trimmed = s.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        trimmed[1..trimmed.len() - 1].to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_nodes_from_json(content: &str) -> Option<Vec<ArchitectureNode>> {
    let val: serde_json::Value = serde_json::from_str(content).ok()?;
    let mut nodes = Vec::new();

    let process_node_obj =
        |node_id: &str, obj: &serde_json::Map<String, serde_json::Value>| -> ArchitectureNode {
            let id = obj
                .get("id")
                .or_else(|| obj.get("name"))
                .or_else(|| obj.get("node"))
                .and_then(|v| v.as_str())
                .unwrap_or(node_id)
                .to_string();

            let node_type = obj
                .get("type")
                .or_else(|| obj.get("layer"))
                .or_else(|| obj.get("kind"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let contract = obj
                .get("contract")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let interface = obj
                .get("interface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let mut depends_on = Vec::new();
            if let Some(deps_val) = obj
                .get("depends_on")
                .or_else(|| obj.get("dependencies"))
                .or_else(|| obj.get("requires"))
            {
                if let Some(arr) = deps_val.as_array() {
                    for elem in arr {
                        if let Some(s) = elem.as_str() {
                            depends_on.push(s.to_string());
                        }
                    }
                } else if let Some(s) = deps_val.as_str() {
                    depends_on.push(s.to_string());
                }
            }

            let mut line_num = 1;
            let mut line_len = 1;
            for (i, l) in content.lines().enumerate() {
                if l.contains(&format!("\"{}\"", id)) || l.contains(&format!("\"id\": \"{}\"", id)) {
                    line_num = (i + 1) as u32;
                    line_len = l.len().max(1) as u32;
                    break;
                }
            }

            ArchitectureNode {
                id,
                node_type,
                contract,
                interface,
                depends_on,
                line: line_num,
                line_len,
            }
        };

    if let Some(obj) = val.as_object() {
        if let Some(nodes_val) = obj
            .get("nodes")
            .or_else(|| obj.get("graph"))
            .or_else(|| obj.get("services"))
            .or_else(|| obj.get("components"))
            .or_else(|| obj.get("modules"))
        {
            if let Some(arr) = nodes_val.as_array() {
                for (idx, elem) in arr.iter().enumerate() {
                    if let Some(n_obj) = elem.as_object() {
                        let fallback_id = format!("node_{}", idx);
                        nodes.push(process_node_obj(&fallback_id, n_obj));
                    }
                }
            } else if let Some(map) = nodes_val.as_object() {
                for (k, v) in map {
                    if let Some(n_obj) = v.as_object() {
                        nodes.push(process_node_obj(k, n_obj));
                    }
                }
            }
        } else {
            for (k, v) in obj {
                if let Some(n_obj) = v.as_object() {
                    if n_obj.contains_key("type")
                        || n_obj.contains_key("depends_on")
                        || n_obj.contains_key("contract")
                        || n_obj.contains_key("interface")
                    {
                        nodes.push(process_node_obj(k, n_obj));
                    }
                }
            }
        }
    } else if let Some(arr) = val.as_array() {
        for (idx, elem) in arr.iter().enumerate() {
            if let Some(n_obj) = elem.as_object() {
                let fallback_id = format!("node_{}", idx);
                nodes.push(process_node_obj(&fallback_id, n_obj));
            }
        }
    }

    if nodes.is_empty() {
        None
    } else {
        Some(nodes)
    }
}

/// Whether `trimmed` begins a new architecture node entry.
/// `has_current` is true when we're already inside a node body.
fn begins_new_node(trimmed: &str, has_current: bool, reserved_keys: &[&str]) -> bool {
    // List entries always start a new node.
    if trimmed.starts_with("- id:")
        || trimmed.starts_with("- name:")
        || trimmed.starts_with("- node:")
    {
        return true;
    }
    // "id:", "name:", "node:" start a new node only without a current one;
    // inside a node body they are field updates handled by parse_yaml_field.
    let is_id_like = trimmed.starts_with("id:")
        || trimmed.starts_with("name:")
        || trimmed.starts_with("node:");
    if is_id_like {
        return !has_current;
    }
    // Non-reserved mapping keys start a new node.
    if trimmed.ends_with(':') {
        let key = trimmed
            .trim_end_matches(':')
            .trim_start_matches("- ")
            .trim();
        return !reserved_keys.contains(&key) && !key.contains(' ');
    }
    false
}

/// Extracts the node id from a YAML node-start line.
fn extract_node_id(trimmed: &str) -> String {
    if trimmed.starts_with("- id:")
        || trimmed.starts_with("id:")
        || trimmed.starts_with("- name:")
        || trimmed.starts_with("name:")
        || trimmed.starts_with("- node:")
        || trimmed.starts_with("node:")
    {
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 {
            return strip_quotes(parts[1]);
        }
    }
    // Mapping-key node: the key itself is the id.
    if trimmed.ends_with(':') {
        let key = trimmed
            .trim_end_matches(':')
            .trim_start_matches("- ")
            .trim();
        return strip_quotes(key);
    }
    String::new()
}

/// Saves the current node (if valid) and resets the slot.
fn save_current_node(
    current_node: &mut Option<ArchitectureNode>,
    nodes: &mut Vec<ArchitectureNode>,
) {
    if let Some(node) = current_node.take() {
        if !node.id.is_empty() {
            nodes.push(node);
        }
    }
}

/// Parses one line as a field of the current architecture node.
/// Updates `in_depends_on`: `true` when inside a multi-line `depends_on`
/// block waiting for list items, reset to `false` by any other field.
fn parse_yaml_field(node: &mut ArchitectureNode, trimmed: &str, in_depends_on: &mut bool) {
    if trimmed.starts_with("id:")
        || trimmed.starts_with("- id:")
        || trimmed.starts_with("name:")
        || trimmed.starts_with("- name:")
    {
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 {
            node.id = strip_quotes(parts[1]);
        }
        return;
    }

    if trimmed.starts_with("type:") || trimmed.starts_with("layer:") || trimmed.starts_with("kind:") {
        *in_depends_on = false;
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 {
            node.node_type = Some(strip_quotes(parts[1]));
        }
        return;
    }

    if trimmed.starts_with("contract:") {
        *in_depends_on = false;
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 {
            node.contract = Some(strip_quotes(parts[1]));
        }
        return;
    }

    if trimmed.starts_with("interface:") {
        *in_depends_on = false;
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 {
            node.interface = Some(strip_quotes(parts[1]));
        }
        return;
    }

    if trimmed.starts_with("depends_on:")
        || trimmed.starts_with("dependencies:")
        || trimmed.starts_with("requires:")
    {
        let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
        if parts.len() == 2 {
            let val = parts[1].trim();
            if val.starts_with('[') && val.ends_with(']') {
                let inner = &val[1..val.len() - 1];
                for item in inner.split(',') {
                    let dep = strip_quotes(item);
                    if !dep.is_empty() {
                        node.depends_on.push(dep);
                    }
                }
                *in_depends_on = false;
            } else if !val.is_empty() {
                node.depends_on.push(strip_quotes(val));
                *in_depends_on = false;
            } else {
                *in_depends_on = true;
            }
        }
        return;
    }

    // Multi-line depends_on list items.
    if *in_depends_on {
        if trimmed.starts_with('-') {
            let dep = strip_quotes(trimmed.trim_start_matches('-'));
            if !dep.is_empty() {
                node.depends_on.push(dep);
            }
        } else if trimmed.contains(':') {
            *in_depends_on = false;
        }
    }
}

fn parse_nodes_from_yaml(content: &str) -> Vec<ArchitectureNode> {
    let mut nodes: Vec<ArchitectureNode> = Vec::new();
    let mut current_node: Option<ArchitectureNode> = None;
    let mut in_depends_on = false;

    let reserved_keys: &[&str] = &[
        "nodes", "graph", "services", "components", "modules",
        "spec", "version", "depends_on", "dependencies", "requires",
        "imports", "contract", "interface", "type", "layer", "kind",
        "description", "metadata", "api_version", "apiVersion",
    ];

    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if begins_new_node(trimmed, current_node.is_some(), reserved_keys) {
            save_current_node(&mut current_node, &mut nodes);
            in_depends_on = false;
            let node = ArchitectureNode {
                line: (idx + 1) as u32,
                line_len: line.len().max(1) as u32,
                id: extract_node_id(trimmed),
                ..ArchitectureNode::default()
            };
            current_node = Some(node);
            continue;
        }

        if let Some(ref mut node) = current_node {
            parse_yaml_field(node, trimmed, &mut in_depends_on);
        }
    }

    save_current_node(&mut current_node, &mut nodes);
    nodes
}

fn parse_architecture_nodes(content: &str) -> Vec<ArchitectureNode> {
    if let Some(json_nodes) = parse_nodes_from_json(content) {
        json_nodes
    } else {
        parse_nodes_from_yaml(content)
    }
}

fn find_cycle<'a>(
    start_id: &'a str,
    curr_id: &'a str,
    nodes_map: &std::collections::HashMap<&'a str, &'a ArchitectureNode>,
    visited: &mut Vec<&'a str>,
) -> Option<String> {
    let curr_node = nodes_map.get(curr_id)?;
    for dep in &curr_node.depends_on {
        let dep_str = dep.as_str();
        if dep_str == start_id {
            let mut cycle = visited.clone();
            cycle.push(start_id);
            return Some(cycle.join(" -> "));
        }
        if !visited.contains(&dep_str) && nodes_map.contains_key(dep_str) {
            visited.push(dep_str);
            if let Some(path) = find_cycle(start_id, dep_str, nodes_map, visited) {
                return Some(path);
            }
            visited.pop();
        }
    }
    None
}

impl Rule for GraphCircularDependencyRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::yaml() || *lang == LanguageIdentifier::json()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        30
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Circular node dependency detected in architecture graph specification file. Node dependency loops in YAML/JSON architecture graphs break acyclic dependency guarantees.".into(),
            tags: vec!["architecture".into(), "graph".into(), "circular-dependency".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let nodes = parse_architecture_nodes(file.content());
        if nodes.is_empty() {
            return Vec::new();
        }

        let nodes_map: std::collections::HashMap<&str, &ArchitectureNode> =
            nodes.iter().map(|n| (n.id.as_str(), n)).collect();

        let mut findings = Vec::new();

        for node in &nodes {
            let mut visited = vec![node.id.as_str()];
            if let Some(cycle_path) = find_cycle(&node.id, &node.id, &nodes_map, &mut visited) {
                let span = Span::new(node.line, 1, node.line, node.line_len);
                findings.push(Finding::new(
                    format!(
                        "Circular node dependency in architecture graph detected for node '{}': {}",
                        node.id, cycle_path
                    ),
                    span,
                ));
            }
        }

        findings
    }
}

impl Rule for GraphMissingContractRule {
    fn id(&self) -> &RuleId {
        &self.id
    }

    fn applies_to(&self, lang: &LanguageIdentifier) -> bool {
        *lang == LanguageIdentifier::yaml() || *lang == LanguageIdentifier::json()
    }

    fn default_severity(&self) -> Severity {
        Severity::Major
    }

    fn issue_type(&self) -> IssueType {
        IssueType::CodeSmell
    }

    fn remediation_effort_minutes(&self) -> u32 {
        20
    }

    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            description: "Domain node in architecture graph missing contract specification. Domain nodes must explicitly define a contract or interface field.".into(),
            tags: vec!["architecture".into(), "graph".into(), "domain".into(), "contract".into()],
            cwe: None,
            produces_hotspots: false,
        }
    }

    fn check(&self, file: &SourceFile, ast: &AstNode) -> Vec<Finding> {
        if ast.kind() != &NodeKind::SourceUnit {
            return Vec::new();
        }

        let nodes = parse_architecture_nodes(file.content());
        let mut findings = Vec::new();

        for node in &nodes {
            if node.is_domain() && !node.has_contract_or_interface() {
                let span = Span::new(node.line, 1, node.line, node.line_len);
                findings.push(Finding::new(
                    format!(
                        "Domain node missing contract specification: node '{}' does not define an explicit contract or interface field",
                        node.id
                    ),
                    span,
                ));
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_unit(code: &str) -> AstNode {
        AstNode::new(
            NodeKind::SourceUnit,
            Span::new(1, 1, 1, code.len() as u32),
            code,
            vec![],
        )
    }

    #[test]
    fn test_yaml_circular_dependency_detected() {
        let code = r#"nodes:
  - id: order-service
    type: domain
    contract: OrderContract
    depends_on:
      - payment-service
  - id: payment-service
    type: domain
    contract: PaymentContract
    depends_on:
      - order-service
"#;
        let file = SourceFile::new("arch.yaml", code, LanguageIdentifier::yaml()).unwrap();
        let ast = source_unit(code);

        let rule = GraphCircularDependencyRule::new();
        let findings = rule.check(&file, &ast);

        assert_eq!(findings.len(), 2);
        assert!(findings[0]
            .message
            .contains("Circular node dependency in architecture graph"));
        assert!(findings[0].message.contains("order-service"));
        assert!(findings[1].message.contains("payment-service"));
    }

    #[test]
    fn test_yaml_acyclic_dependency_passes() {
        let code = r#"nodes:
  - id: order-service
    type: domain
    contract: OrderContract
    depends_on:
      - payment-service
  - id: payment-service
    type: domain
    contract: PaymentContract
"#;
        let file = SourceFile::new("arch.yaml", code, LanguageIdentifier::yaml()).unwrap();
        let ast = source_unit(code);

        let rule = GraphCircularDependencyRule::new();
        let findings = rule.check(&file, &ast);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_json_circular_dependency_detected() {
        let code = r#"{
  "nodes": [
    {
      "id": "A",
      "type": "domain",
      "contract": "ContractA",
      "depends_on": ["B"]
    },
    {
      "id": "B",
      "type": "domain",
      "contract": "ContractB",
      "depends_on": ["A"]
    }
  ]
}"#;
        let file = SourceFile::new("arch.json", code, LanguageIdentifier::json()).unwrap();
        let ast = source_unit(code);

        let rule = GraphCircularDependencyRule::new();
        let findings = rule.check(&file, &ast);

        assert_eq!(findings.len(), 2);
        assert!(findings[0]
            .message
            .contains("Circular node dependency in architecture graph"));
    }

    #[test]
    fn test_domain_missing_contract_detected() {
        let code = r#"nodes:
  - id: order-service
    type: domain
    depends_on:
      - payment-service
  - id: payment-service
    type: domain
    contract: PaymentContract
"#;
        let file = SourceFile::new("arch.yaml", code, LanguageIdentifier::yaml()).unwrap();
        let ast = source_unit(code);

        let rule = GraphMissingContractRule::new();
        let findings = rule.check(&file, &ast);

        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .message
            .contains("Domain node missing contract specification"));
        assert!(findings[0].message.contains("order-service"));
    }

    #[test]
    fn test_domain_node_with_interface_passes() {
        let code = r#"nodes:
  - id: order-domain
    type: domain
    interface: OrderInterface
"#;
        let file = SourceFile::new("arch.yaml", code, LanguageIdentifier::yaml()).unwrap();
        let ast = source_unit(code);

        let rule = GraphMissingContractRule::new();
        let findings = rule.check(&file, &ast);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_non_domain_node_without_contract_passes() {
        let code = r#"nodes:
  - id: http-adapter
    type: adapter
"#;
        let file = SourceFile::new("arch.yaml", code, LanguageIdentifier::yaml()).unwrap();
        let ast = source_unit(code);

        let rule = GraphMissingContractRule::new();
        let findings = rule.check(&file, &ast);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_applies_to() {
        let rule_circ = GraphCircularDependencyRule::new();
        let rule_contract = GraphMissingContractRule::new();

        assert!(rule_circ.applies_to(&LanguageIdentifier::yaml()));
        assert!(rule_circ.applies_to(&LanguageIdentifier::json()));
        assert!(!rule_circ.applies_to(&LanguageIdentifier::rust()));

        assert!(rule_contract.applies_to(&LanguageIdentifier::yaml()));
        assert!(rule_contract.applies_to(&LanguageIdentifier::json()));
        assert!(!rule_contract.applies_to(&LanguageIdentifier::typescript()));
    }
}
