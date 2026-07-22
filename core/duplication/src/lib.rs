//! Copy-paste detection (CPD): finds duplicated blocks of normalized lines
//! within and across files using rolling window hashes, then merges
//! overlapping window matches into maximal blocks. Pure core — std only.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};

use yunq_ast::SourceFile;

#[derive(Clone, Copy, Debug)]
pub struct DuplicationConfig {
    /// Minimum number of significant (non-blank) lines a block must span.
    pub min_lines: usize,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self { min_lines: 10 }
    }
}

/// One side of a duplicate pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
}

/// Two regions with identical normalized content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DuplicateBlock {
    pub first: BlockRef,
    pub second: BlockRef,
    /// Number of duplicated significant lines.
    pub lines: usize,
}

/// Aggregate duplication result for one analysis.
#[derive(Clone, Debug, Default)]
pub struct DuplicationReport {
    pub blocks: Vec<DuplicateBlock>,
    /// Distinct (file, line) pairs involved in any duplication.
    pub duplicated_lines: usize,
}

struct SignificantLine {
    /// 1-based line number in the original file.
    line_number: u32,
    hash: u64,
}

fn significant_lines(file: &SourceFile) -> Vec<SignificantLine> {
    file.content()
        .lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut hasher = DefaultHasher::new();
            trimmed.hash(&mut hasher);
            Some(SignificantLine { line_number: index as u32 + 1, hash: hasher.finish() })
        })
        .collect()
}

pub fn find_duplicates(files: &[SourceFile], config: DuplicationConfig) -> DuplicationReport {
    let min = config.min_lines.max(2);
    let per_file: Vec<(usize, Vec<SignificantLine>)> =
        files.iter().enumerate().map(|(i, f)| (i, significant_lines(f))).collect();

    // window hash -> first occurrence (file index, window start offset)
    let mut seen: HashMap<u64, (usize, usize)> = HashMap::new();
    // (file_a, file_b, offset_delta) -> matched window starts in file_b
    let mut matches: BTreeMap<(usize, usize, isize), BTreeSet<usize>> = BTreeMap::new();

    for (file_index, lines) in &per_file {
        if lines.len() < min {
            continue;
        }
        for start in 0..=(lines.len() - min) {
            let mut hasher = DefaultHasher::new();
            for line in &lines[start..start + min] {
                line.hash.hash(&mut hasher);
            }
            let window_hash = hasher.finish();
            match seen.get(&window_hash) {
                None => {
                    seen.insert(window_hash, (*file_index, start));
                }
                Some(&(first_file, first_start)) => {
                    // Ignore self-overlapping windows within one file.
                    if first_file == *file_index && start < first_start + min {
                        continue;
                    }
                    let delta = start as isize - first_start as isize;
                    matches
                        .entry((first_file, *file_index, delta))
                        .or_default()
                        .insert(start);
                }
            }
        }
    }

    // Merge consecutive matched windows into maximal blocks.
    let mut blocks = Vec::new();
    let mut duplicated: BTreeSet<(usize, u32)> = BTreeSet::new();
    for ((file_a, file_b, delta), starts) in matches {
        let mut run_start: Option<usize> = None;
        let mut previous: Option<usize> = None;
        let flush =
            |run_start: usize, run_end: usize, blocks: &mut Vec<DuplicateBlock>, duplicated: &mut BTreeSet<(usize, u32)>| {
                let lines_b = &per_file[file_b].1;
                let lines_a = &per_file[file_a].1;
                let len = run_end - run_start + min;
                let b_slice = &lines_b[run_start..run_start + len];
                let a_start = (run_start as isize - delta) as usize;
                let a_slice = &lines_a[a_start..a_start + len];
                for line in b_slice {
                    duplicated.insert((file_b, line.line_number));
                }
                for line in a_slice {
                    duplicated.insert((file_a, line.line_number));
                }
                blocks.push(DuplicateBlock {
                    first: BlockRef {
                        file: files[file_a].path().to_string(),
                        start_line: a_slice[0].line_number,
                        end_line: a_slice[len - 1].line_number,
                    },
                    second: BlockRef {
                        file: files[file_b].path().to_string(),
                        start_line: b_slice[0].line_number,
                        end_line: b_slice[len - 1].line_number,
                    },
                    lines: len,
                });
            };
        for &start in &starts {
            match previous {
                Some(prev) if start == prev + 1 => {}
                Some(prev) => {
                    flush(run_start.unwrap(), prev, &mut blocks, &mut duplicated);
                    run_start = Some(start);
                }
                None => run_start = Some(start),
            }
            previous = Some(start);
        }
        if let (Some(rs), Some(prev)) = (run_start, previous) {
            flush(rs, prev, &mut blocks, &mut duplicated);
        }
    }

    DuplicationReport { blocks, duplicated_lines: duplicated.len() }
}

#[cfg(test)]
mod tests {
    use yunq_ast::LanguageIdentifier;

    use super::*;

    fn file(path: &str, content: &str) -> SourceFile {
        SourceFile::new(path, content, LanguageIdentifier::rust()).unwrap()
    }

    fn block_body(prefix: &str) -> String {
        (0..6).map(|i| format!("    let {prefix}_{i} = compute({i});\n")).collect()
    }

    #[test]
    fn detects_cross_file_duplicates_and_merges_windows() {
        let shared: String = (0..8).map(|i| format!("    total += weights[{i}] * {i};\n")).collect();
        let a = format!("fn a() {{\n{shared}}}\n");
        let b = format!("fn b() {{\n\n{shared}}}\n");
        let files = [file("a.rs", &a), file("b.rs", &b)];

        let report = find_duplicates(&files, DuplicationConfig { min_lines: 5 });
        assert_eq!(report.blocks.len(), 1);
        let block = &report.blocks[0];
        // 8 shared body lines + the identical closing brace line.
        assert_eq!(block.lines, 9);
        assert_eq!(block.first.file, "a.rs");
        assert_eq!(block.second.file, "b.rs");
        assert_eq!(report.duplicated_lines, 18);
    }

    #[test]
    fn distinct_content_produces_no_blocks() {
        let files = [
            file("a.rs", &format!("fn a() {{\n{}}}\n", block_body("alpha"))),
            file("b.rs", &format!("fn b() {{\n{}}}\n", block_body("beta"))),
        ];
        let report = find_duplicates(&files, DuplicationConfig { min_lines: 5 });
        assert!(report.blocks.is_empty());
        assert_eq!(report.duplicated_lines, 0);
    }

    #[test]
    fn short_files_are_ignored() {
        let files = [file("a.rs", "let x = 1;\n"), file("b.rs", "let x = 1;\n")];
        let report = find_duplicates(&files, DuplicationConfig::default());
        assert!(report.blocks.is_empty());
    }
}
