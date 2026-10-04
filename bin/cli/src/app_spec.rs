//! A neutral, deterministic description of the app a kickoff should create:
//! entities with typed fields. From it vord derives the engine blueprint
//! (ferrum's graph) and the OpenAPI contract, so the agent never writes
//! either by hand.

use std::collections::BTreeMap;

/// Field types every derivation understands.
pub const FIELD_TYPES: &[&str] = &["string", "int", "float", "bool", "uuid", "datetime"];

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppSpec {
    pub name: String,
    /// Entity name (lowercase singular, e.g. `todo`) -> field -> type.
    pub entities: BTreeMap<String, BTreeMap<String, String>>,
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn plural(name: &str) -> String {
    match name.strip_suffix('y') {
        Some(stem) if !stem.ends_with(['a', 'e', 'i', 'o', 'u']) => format!("{stem}ies"),
        _ if name.ends_with('s') => format!("{name}es"),
        _ => format!("{name}s"),
    }
}

fn pascal(name: &str) -> String {
    name.split('_')
        .map(|w| {
            let mut c = w.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect()
}

impl AppSpec {
    /// `--entity todo:title=string,done=bool` (repeatable).
    pub fn from_entity_flags(name: &str, flags: &[String]) -> anyhow::Result<Self> {
        let mut entities = BTreeMap::new();
        for flag in flags {
            let (entity, fields) = flag.split_once(':').ok_or_else(|| {
                anyhow::anyhow!("--entity expects name:field=type,field=type, got {flag:?}")
            })?;
            let mut map = BTreeMap::new();
            for pair in fields.split(',').filter(|p| !p.is_empty()) {
                let (field, ty) = pair
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("--entity field {pair:?} must be field=type"))?;
                map.insert(field.trim().to_string(), ty.trim().to_string());
            }
            entities.insert(entity.trim().to_string(), map);
        }
        let spec = Self {
            name: name.to_string(),
            entities,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// `{"name": "todo", "entities": {"todo": {"title": "string", "done": "bool"}}}`.
    pub fn from_json(raw: &str) -> anyhow::Result<Self> {
        let spec: Self = serde_json::from_str(raw)
            .map_err(|e| anyhow::anyhow!("invalid app description: {e}"))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.entities.is_empty() {
            anyhow::bail!("the app needs at least one entity");
        }
        for (entity, fields) in &self.entities {
            if !is_ident(entity) {
                anyhow::bail!(
                    "entity name {entity:?} must be lowercase letters, digits or _ and start with a letter"
                );
            }
            if fields.is_empty() {
                anyhow::bail!("entity {entity:?} has no fields");
            }
            for (field, ty) in fields {
                if !is_ident(field) || field == "id" {
                    anyhow::bail!(
                        "field {entity}.{field} must be a lowercase identifier other than id (ids are generated)"
                    );
                }
                if !FIELD_TYPES.contains(&ty.as_str()) {
                    anyhow::bail!(
                        "field {entity}.{field}: unknown type {ty:?} (use {})",
                        FIELD_TYPES.join(", ")
                    );
                }
            }
        }
        Ok(())
    }

    /// The ferrum graph (`gen/<name>.yaml`): one module per entity with the
    /// five CRUD use cases.
    pub fn ferrum_graph(&self) -> String {
        let mut out = format!(
            "# Derived by `vord kickoff` from app.json; edit app.json, not this file.\napp:\n  name: {0}\n  title: {0}\n  version: \"0.1.0\"\n  database: postgres\n\nmodules:\n",
            self.name
        );
        for (entity, fields) in &self.entities {
            let (plural, pascal) = (plural(entity), pascal(entity));
            out.push_str(&format!("  {plural}:\n    entity:\n      fields:\n"));
            for (field, ty) in fields {
                out.push_str(&format!("        {field}: {ty}\n"));
            }
            out.push_str("    usecases:\n");
            out.push_str(&format!(
                "      list{}:\n        input:\n          limit: int\n        output: {pascal}\n",
                pascal_plural(entity)
            ));
            out.push_str(&format!(
                "      get{pascal}:\n        input:\n          id: uuid\n        output: {pascal}\n"
            ));
            for verb in ["create", "update"] {
                out.push_str(&format!("      {verb}{pascal}:\n        input:\n"));
                if verb == "update" {
                    out.push_str("          id: uuid\n");
                }
                for (field, ty) in fields {
                    out.push_str(&format!("          {field}: {ty}\n"));
                }
                out.push_str(&format!("        output: {pascal}\n"));
            }
            out.push_str(&format!("      delete{pascal}:\n        input:\n          id: uuid\n        output: {pascal}\n"));
        }
        out
    }

    /// The REST contract: list/create on `/<plural>`, get/update/delete on
    /// `/<plural>/{id}`, with `<Entity>` and `New<Entity>` schemas.
    pub fn openapi(&self) -> String {
        let mut paths = String::new();
        let mut schemas = String::new();
        for (entity, fields) in &self.entities {
            let (plural, pascal) = (plural(entity), pascal(entity));
            paths.push_str(&format!(
                "  /{plural}:\n    get:\n      operationId: list{pl}\n      responses:\n        '200':\n          description: All {plural}\n          content:\n            application/json:\n              schema:\n                type: array\n                items: {{ $ref: '#/components/schemas/{pascal}' }}\n    post:\n      operationId: create{pascal}\n      requestBody:\n        required: true\n        content:\n          application/json:\n            schema: {{ $ref: '#/components/schemas/New{pascal}' }}\n      responses:\n        '201':\n          description: Created\n          content:\n            application/json:\n              schema: {{ $ref: '#/components/schemas/{pascal}' }}\n",
                pl = pascal_plural(entity)
            ));
            let id_param = "      parameters:\n        - { name: id, in: path, required: true, schema: { type: string, format: uuid } }\n";
            paths.push_str(&format!(
                "  /{plural}/{{id}}:\n    get:\n      operationId: get{pascal}\n{id_param}      responses:\n        '200':\n          description: The {entity}\n          content:\n            application/json:\n              schema: {{ $ref: '#/components/schemas/{pascal}' }}\n        '404': {{ description: Not found }}\n    put:\n      operationId: update{pascal}\n{id_param}      requestBody:\n        required: true\n        content:\n          application/json:\n            schema: {{ $ref: '#/components/schemas/New{pascal}' }}\n      responses:\n        '200':\n          description: Updated\n          content:\n            application/json:\n              schema: {{ $ref: '#/components/schemas/{pascal}' }}\n        '404': {{ description: Not found }}\n    delete:\n      operationId: delete{pascal}\n{id_param}      responses:\n        '204': {{ description: Deleted }}\n        '404': {{ description: Not found }}\n"
            ));
            let props: String = fields
                .iter()
                .map(|(f, t)| format!("        {f}: {}\n", openapi_type(t)))
                .collect();
            let required: String = fields.keys().map(|f| format!("        - {f}\n")).collect();
            schemas.push_str(&format!(
                "    New{pascal}:\n      type: object\n      required:\n{required}      properties:\n{props}    {pascal}:\n      type: object\n      required:\n        - id\n{required}      properties:\n        id: {{ type: string, format: uuid }}\n{props}"
            ));
        }
        format!(
            "openapi: 3.0.3\ninfo:\n  title: {}\n  version: 0.1.0\n# Derived by `vord kickoff` from app.json; edit app.json and regenerate.\npaths:\n{paths}components:\n  schemas:\n{schemas}",
            self.name
        )
    }
}

fn pascal_plural(entity: &str) -> String {
    pascal(&plural(entity))
}

fn openapi_type(ty: &str) -> &'static str {
    match ty {
        "string" => "{ type: string }",
        "int" => "{ type: integer }",
        "float" => "{ type: number }",
        "bool" => "{ type: boolean }",
        "uuid" => "{ type: string, format: uuid }",
        _ => "{ type: string, format: date-time }",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn todo() -> AppSpec {
        AppSpec::from_entity_flags("todo", &["todo:title=string,done=bool".to_string()]).unwrap()
    }

    #[test]
    fn entity_flags_and_json_agree() {
        let json = AppSpec::from_json(
            r#"{"name":"todo","entities":{"todo":{"title":"string","done":"bool"}}}"#,
        )
        .unwrap();
        assert_eq!(json, todo());
    }

    #[test]
    fn bad_descriptions_are_rejected_with_the_reason() {
        for (flags, msg) in [
            (vec!["todo:title=text"], "unknown type"),
            (vec!["todo:id=uuid"], "other than id"),
            (vec!["Todo:title=string"], "lowercase"),
            (vec!["todo"], "name:field=type"),
            (vec![], "at least one entity"),
        ] {
            let flags: Vec<String> = flags.into_iter().map(String::from).collect();
            let err = AppSpec::from_entity_flags("x", &flags)
                .unwrap_err()
                .to_string();
            assert!(err.contains(msg), "{err}");
        }
    }

    #[test]
    fn the_ferrum_graph_has_crud_use_cases_with_the_fields() {
        let graph = todo().ferrum_graph();
        for expected in [
            "todos:",
            "listTodos:",
            "getTodo:",
            "createTodo:",
            "updateTodo:",
            "deleteTodo:",
            "done: bool",
            "title: string",
        ] {
            assert!(graph.contains(expected), "{expected} missing in {graph}");
        }
    }

    #[test]
    fn the_contract_declares_crud_paths_and_schemas() {
        let spec = todo().openapi();
        for expected in [
            "/todos:",
            "/todos/{id}:",
            "operationId: createTodo",
            "NewTodo:",
            "type: boolean",
            "format: uuid",
        ] {
            assert!(spec.contains(expected), "{expected} missing in {spec}");
        }
    }

    #[test]
    fn plurals_follow_english_basics() {
        assert_eq!(plural("todo"), "todos");
        assert_eq!(plural("category"), "categories");
        assert_eq!(plural("day"), "days");
        assert_eq!(plural("status"), "statuses");
    }
}
