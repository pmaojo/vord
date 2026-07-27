//! Project features: tags, favorites, export/import. ROADMAP §Phase 4 —
//! "Project features: badges, links, tags, favorites, project export/
//! import between instances".
//!
//! Skeleton: types + a small in-memory store + the export/import
//! serialization round-trip are in place; the Postgres store + HTTP routes
//! land in following iterations.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// One project feature tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectTag {
    pub project_key: String,
    pub tag: String,
}

impl ProjectTag {
    pub fn is_valid(tag: &str) -> bool {
        !tag.is_empty() && tag.len() <= 64 && tag.chars().all(|c| !c.is_control())
    }
}

/// One user's favorite of one project.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProjectFavorite {
    pub user_id: String,
    pub project_key: String,
}

/// A full project export — settings + tags + favorites + last gate
/// result snapshot, in a portable shape so two yunq instances can swap.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProjectExport {
    pub project_key: String,
    pub name: String,
    pub description: String,
    pub visibility: String,            // public|private
    pub language: String,
    pub tags: Vec<String>,
    pub quality_gate_name: Option<String>,
    pub quality_profile_name: Option<String>,
    pub new_code_override: Option<String>,  // raw JSON of NewCodeOverride
    pub retention_days: Option<i32>,
}

impl ProjectExport {
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    pub fn from_json(raw: &str) -> Result<Self, String> {
        serde_json::from_str(raw).map_err(|e| e.to_string())
    }
}

#[derive(Default)]
pub struct ProjectFeatureStore {
    tags: HashMap<String, HashSet<String>>,           // project_key -> tags
    favorites: HashMap<String, HashSet<String>>,       // user_id -> project_keys
}

impl ProjectFeatureStore {
    pub fn add_tag(&mut self, project: &str, tag: &str) -> Result<(), String> {
        if !ProjectTag::is_valid(tag) { return Err(format!("invalid tag {tag:?}")); }
        self.tags.entry(project.to_string()).or_default().insert(tag.to_string());
        Ok(())
    }
    pub fn remove_tag(&mut self, project: &str, tag: &str) -> bool {
        let Some(s) = self.tags.get_mut(project) else { return false; };
        let removed = s.remove(tag);
        if s.is_empty() { self.tags.remove(project); }
        removed
    }
    pub fn tags_for(&self, project: &str) -> Vec<String> {
        let mut v: Vec<String> = self.tags.get(project).cloned().unwrap_or_default().into_iter().collect();
        v.sort();
        v
    }
    pub fn favorite(&mut self, user: &str, project: &str) {
        self.favorites.entry(user.to_string()).or_default().insert(project.to_string());
    }
    pub fn unfavorite(&mut self, user: &str, project: &str) -> bool {
        let Some(s) = self.favorites.get_mut(user) else { return false; };
        let r = s.remove(project);
        if s.is_empty() { self.favorites.remove(user); }
        r
    }
    pub fn favorites_of(&self, user: &str) -> Vec<String> {
        let mut v: Vec<String> = self.favorites.get(user).cloned().unwrap_or_default().into_iter().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_then_remove_tag_round_trips() {
        let mut s = ProjectFeatureStore::default();
        s.add_tag("yunq", "team/platform").unwrap();
        s.add_tag("yunq", "team/infra").unwrap();
        assert_eq!(s.tags_for("yunq"), vec!["team/infra", "team/platform"]);
        assert!(s.remove_tag("yunq", "team/platform"));
        assert_eq!(s.tags_for("yunq"), vec!["team/infra"]);
    }

    #[test]
    fn invalid_tag_is_rejected() {
        let mut s = ProjectFeatureStore::default();
        assert!(s.add_tag("yunq", "").is_err());
        assert!(s.add_tag("yunq", &"x".repeat(65)).is_err());
    }

    #[test]
    fn favorite_then_unfavorite_round_trips() {
        let mut s = ProjectFeatureStore::default();
        s.favorite("alice", "yunq");
        s.favorite("alice", "yunq-frontend");
        assert_eq!(s.favorites_of("alice"), vec!["yunq", "yunq-frontend"]);
        assert!(s.unfavorite("alice", "yunq"));
        assert_eq!(s.favorites_of("alice"), vec!["yunq-frontend"]);
    }

    #[test]
    fn project_export_round_trips_through_json() {
        let original = ProjectExport {
            project_key: "yunq".to_string(),
            name: "yunq core".to_string(),
            description: "Static analysis platform".to_string(),
            visibility: "private".to_string(),
            language: "rust".to_string(),
            tags: vec!["team/platform".to_string(), "team/infra".to_string()],
            quality_gate_name: Some("yunq-default".to_string()),
            quality_profile_name: Some("yunq way".to_string()),
            new_code_override: Some("{\"Days\":7}".to_string()),
            retention_days: Some(90),
        };
        let json = original.to_json().unwrap();
        let restored = ProjectExport::from_json(&json).unwrap();
        assert_eq!(original, restored);
    }

    #[test]
    fn project_export_rejects_malformed_json() {
        let r = ProjectExport::from_json("not json");
        assert!(r.is_err());
    }

    #[test]
    fn project_export_missing_required_field_fails() {
        let r = ProjectExport::from_json(r#"{"project_key":"yunq"}"#);
        assert!(r.is_err());
    }

    #[test]
    fn project_tag_validation_matches_issue_tag_rules() {
        assert!(ProjectTag::is_valid("ok"));
        assert!(ProjectTag::is_valid("with-dash"));
        assert!(ProjectTag::is_valid("with/slash"));
        assert!(!ProjectTag::is_valid(""));
        assert!(!ProjectTag::is_valid(&"x".repeat(65)));
    }
}
