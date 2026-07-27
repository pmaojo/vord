//! Outbound adapter: SCM blame persistence — the server-side counterpart to
//! the CLI's `--blame-output` (issue #33), ingested via
//! `POST /api/projects/{key}/blame` so the `sources` endpoint (issue #26)
//! can annotate lines with who last touched them. Lives alongside
//! `PgIssueStorage`/`coverage.rs` (same pool, same database, same
//! per-analysis-line-detail shape).

use std::collections::BTreeMap;

use sqlx::{Postgres, QueryBuilder, Row};
use yunq_rules_engine::{
    BlameLineInfo, FileBlame, FileBlameLineReader, FileBlameLineStorage, FileBlameLines,
    StorageError,
};

use crate::PgIssueStorage;

fn storage_err(e: impl std::fmt::Display) -> StorageError {
    StorageError(e.to_string())
}

/// Postgres binds at most 65535 parameters per statement; blame rows bind 7
/// columns each, matching the batching convention `IssueStorage::save_issues`
/// already uses.
const BLAME_LINE_BATCH_ROWS: usize = 700;

impl FileBlameLineStorage for PgIssueStorage {
    async fn save_file_blame_lines(
        &self,
        analysis_id: i64,
        files: &[FileBlame],
    ) -> Result<(), StorageError> {
        let mut rows: Vec<(&str, u32, &BlameLineInfo)> = Vec::new();
        for file in files {
            for (line, info) in file.lines() {
                rows.push((file.path(), *line, info));
            }
        }
        if rows.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await.map_err(storage_err)?;
        // Re-ingesting blame for the same analysis replaces its line detail
        // rather than accumulating duplicates, same convention as
        // `save_file_coverage_lines`.
        sqlx::query("DELETE FROM analysis_file_blame_lines WHERE analysis_id = $1")
            .bind(analysis_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_err)?;

        for chunk in rows.chunks(BLAME_LINE_BATCH_ROWS) {
            let mut builder = QueryBuilder::<Postgres>::new(
                "INSERT INTO analysis_file_blame_lines
                    (analysis_id, file, line_number, commit_sha, author, author_mail, author_time, summary) ",
            );
            builder.push_values(chunk, |mut row, (file, line, info)| {
                row.push_bind(analysis_id)
                    .push_bind(*file)
                    .push_bind(*line as i32)
                    .push_bind(&info.commit)
                    .push_bind(&info.author)
                    .push_bind(&info.author_mail)
                    .push_bind(info.author_time)
                    .push_bind(&info.summary);
            });
            builder
                .build()
                .execute(&mut *tx)
                .await
                .map_err(storage_err)?;
        }
        tx.commit().await.map_err(storage_err)
    }
}

impl FileBlameLineReader for PgIssueStorage {
    async fn file_blame_lines(
        &self,
        project_key: &str,
        branch: &str,
        file: &str,
    ) -> Result<Option<FileBlameLines>, StorageError> {
        // Scoped to the project's most recent analysis that has blame
        // ingested at all (not necessarily the very latest analysis — a scan
        // may have run since the last blame upload), mirroring
        // `file_coverage_lines`'s own "most recent data-bearing analysis"
        // semantics.
        let rows = sqlx::query(
            "SELECT l.line_number, l.commit_sha, l.author, l.author_mail, l.author_time, l.summary
             FROM analysis_file_blame_lines l
             JOIN analyses a ON a.id = l.analysis_id
             JOIN projects p ON p.id = a.project_id
             WHERE p.key = $1 AND a.branch = $2 AND l.file = $3
               AND l.analysis_id = (
                   SELECT b.analysis_id FROM analysis_file_blame_lines b
                   JOIN analyses a2 ON a2.id = b.analysis_id
                   WHERE a2.project_id = a.project_id AND a2.branch = $2
                   ORDER BY b.analysis_id DESC LIMIT 1
               )
             ORDER BY l.line_number ASC",
        )
        .bind(project_key)
        .bind(branch)
        .bind(file)
        .fetch_all(&self.pool)
        .await
        .map_err(storage_err)?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut lines = BTreeMap::new();
        for row in &rows {
            let line: i32 = row.try_get("line_number").map_err(storage_err)?;
            let commit: String = row.try_get("commit_sha").map_err(storage_err)?;
            let author: String = row.try_get("author").map_err(storage_err)?;
            let author_mail: String = row.try_get("author_mail").map_err(storage_err)?;
            let author_time: i64 = row.try_get("author_time").map_err(storage_err)?;
            let summary: String = row.try_get("summary").map_err(storage_err)?;
            lines.insert(
                line as u32,
                BlameLineInfo {
                    commit,
                    author,
                    author_mail,
                    author_time,
                    summary,
                },
            );
        }
        Ok(Some(FileBlameLines { lines }))
    }
}

#[cfg(test)]
mod live_db_tests {
    use super::*;
    use crate::PgIssueStorage;

    async fn connected_storage() -> PgIssueStorage {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://yunq:yunq@localhost:5432/yunq".to_string());
        let storage = PgIssueStorage::connect_lazy(&database_url).unwrap();
        storage.migrate().await.unwrap();
        storage
    }

    fn unique_key(prefix: &str) -> String {
        format!(
            "{prefix}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    fn info(commit: &str, author: &str) -> BlameLineInfo {
        BlameLineInfo {
            commit: commit.to_string(),
            author: author.to_string(),
            author_mail: format!("{author}@example.com"),
            author_time: 1_700_000_000,
            summary: "a commit".to_string(),
        }
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn save_and_read_round_trip_per_line_blame() {
        let storage = connected_storage().await;
        let key = unique_key("blame-test");
        let project_id = storage.ensure_project(&key).await.unwrap();
        let analysis_id = storage
            .record_analysis(project_id, "main", 10, 0)
            .await
            .unwrap();

        let mut file = FileBlame::new("src/a.rs");
        file.record_line(1, info("aaaa", "Jane"));
        file.record_line(2, info("bbbb", "Bob"));
        storage
            .save_file_blame_lines(analysis_id, &[file])
            .await
            .unwrap();

        let blame = storage
            .file_blame_lines(&key, "main", "src/a.rs")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blame.lines.len(), 2);
        assert_eq!(blame.lines[&1].author, "Jane");
        assert_eq!(blame.lines[&2].commit, "bbbb");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn file_blame_lines_is_none_without_any_ingested_blame() {
        let storage = connected_storage().await;
        let key = unique_key("blame-empty-test");
        storage.ensure_project(&key).await.unwrap();
        assert_eq!(
            storage
                .file_blame_lines(&key, "main", "src/a.rs")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; see module docs"]
    async fn re_ingesting_blame_replaces_rather_than_accumulates() {
        let storage = connected_storage().await;
        let key = unique_key("blame-reingest-test");
        let project_id = storage.ensure_project(&key).await.unwrap();
        let analysis_id = storage
            .record_analysis(project_id, "main", 10, 0)
            .await
            .unwrap();

        let mut first = FileBlame::new("src/a.rs");
        first.record_line(1, info("aaaa", "Jane"));
        storage
            .save_file_blame_lines(analysis_id, &[first])
            .await
            .unwrap();

        let mut second = FileBlame::new("src/a.rs");
        second.record_line(1, info("cccc", "Carl"));
        storage
            .save_file_blame_lines(analysis_id, &[second])
            .await
            .unwrap();

        let blame = storage
            .file_blame_lines(&key, "main", "src/a.rs")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blame.lines.len(), 1);
        assert_eq!(blame.lines[&1].author, "Carl");
    }
}
