//! Copy-paste detection (CPD) by block hashing:
//!
//! 1. Runs of consecutive statements with identical content are collapsed to
//!    their first and last occurrence, so e.g. fifty blank `println();`
//!    lines in a row don't themselves register as one giant duplicate.
//! 2. Statements are grouped into fixed-size blocks (`block_size`, default
//!    5) hashed with an incremental Rabin-Karp rolling hash using prime
//!    base 31 (`s[0]*31^(n-1) + ... + s[n-1]`), computed in O(1) per block
//!    rather than re-hashing each window from scratch.
//! 3. Blocks are indexed by hash across *all* files at once: a duplicate is
//!    found by hash lookup, never by comparing every pair of files against
//!    each other.
//! 4. Runs of adjacent matching blocks are merged into maximal duplicated
//!    line ranges.
//!
//! The "statement" unit is one source line's worth of tokens, normalized by
//! whichever `AstParser` is registered for that file's language (leaf-level
//! tree-sitter walk in `vord-treesitter-tokens`: literal values collapsed
//! to placeholders, comments dropped, intra-line whitespace insignificant —
//! see `parsers/treesitter-tokens`). Languages without a registered parser
//! fall back to [`fallback_tokenize`]'s trimmed-line behavior. Pure core —
//! std only, no tree-sitter dependency.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{DefaultHasher, Hash, Hasher};

use vord_ast::SourceFile;

const PRIME_BASE: u64 = 31;

/// One file's per-line, already-normalized token text — produced by an
/// `AstParser::tokenize_for_duplication` override, or [`fallback_tokenize`]
/// when no such parser is registered. `line_number` is 1-based; blank or
/// otherwise insignificant lines (e.g. comment-only, under a real
/// tokenizer) are omitted.
#[derive(Clone, Debug)]
pub struct TokenizedFile {
    pub path: String,
    pub lines: Vec<(u32, String)>,
}

/// Non-language-aware fallback: each non-blank trimmed source line is its
/// own single-token "statement". Used for files whose language has no
/// registered `AstParser`, so duplication detection still degrades
/// gracefully rather than skipping the file.
pub fn fallback_tokenize(file: &SourceFile) -> Vec<(u32, String)> {
    file.content()
        .lines()
        .enumerate()
        .filter_map(|(index, raw)| {
            let trimmed = raw.trim();
            (!trimmed.is_empty()).then(|| (index as u32 + 1, trimmed.to_string()))
        })
        .collect()
}

#[derive(Clone, Copy, Debug)]
pub struct DuplicationConfig {
    /// Number of consecutive statements per hashed block (default 5).
    pub block_size: usize,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self { block_size: 5 }
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

#[derive(Clone, Copy)]
struct Statement {
    /// 1-based line number in the original file.
    line_number: u32,
    hash: u64,
}

fn statements(file: &TokenizedFile) -> Vec<Statement> {
    file.lines
        .iter()
        .map(|(line_number, text)| {
            let mut hasher = DefaultHasher::new();
            text.hash(&mut hasher);
            Statement { line_number: *line_number, hash: hasher.finish() }
        })
        .collect()
}

/// Collapses runs of consecutive statements with identical content down to
/// their first and last occurrence — `BlockChunker`'s deduplication of
/// repeated statements, so a long repeated run doesn't itself inflate a
/// match.
fn collapse_repeats(statements: Vec<Statement>) -> Vec<Statement> {
    let mut out = Vec::with_capacity(statements.len());
    let mut i = 0;
    while i < statements.len() {
        let mut j = i + 1;
        while j < statements.len() && statements[j].hash == statements[i].hash {
            j += 1;
        }
        out.push(statements[i]);
        if j - 1 > i {
            out.push(statements[j - 1]);
        }
        i = j;
    }
    out
}

#[derive(Clone, Copy)]
struct Block {
    /// Index range (inclusive) into the collapsed statement array this
    /// block spans.
    stmt_start: usize,
    stmt_end: usize,
    hash: u64,
}

/// Chunks statements into fixed-size blocks with an incremental Rabin-Karp
/// rolling hash, exactly mirroring `BlockChunker`.
fn chunk_blocks(statements: &[Statement], block_size: usize) -> Vec<Block> {
    if statements.len() < block_size {
        return Vec::new();
    }
    let mut power: u64 = 1;
    for _ in 0..block_size - 1 {
        power = power.wrapping_mul(PRIME_BASE);
    }

    let mut hash: u64 = 0;
    for s in &statements[..block_size - 1] {
        hash = hash.wrapping_mul(PRIME_BASE).wrapping_add(s.hash);
    }

    let mut blocks = Vec::with_capacity(statements.len() - block_size + 1);
    for (first, last) in ((block_size - 1)..statements.len()).enumerate() {
        hash = hash.wrapping_mul(PRIME_BASE).wrapping_add(statements[last].hash);
        blocks.push(Block { stmt_start: first, stmt_end: last, hash });
        // Remove the outgoing statement from the rolling hash.
        hash = hash.wrapping_sub(power.wrapping_mul(statements[first].hash));
    }
    blocks
}

/// Hash -> every (file, block index) that produced it, across all files —
/// duplicates are found by hash lookup, not by comparing every pair of
/// files against each other.
fn build_hash_index(per_file_blocks: &[Vec<Block>]) -> HashMap<u64, Vec<(usize, usize)>> {
    let mut index: HashMap<u64, Vec<(usize, usize)>> = HashMap::new();
    for (file_index, blocks) in per_file_blocks.iter().enumerate() {
        for (block_index, block) in blocks.iter().enumerate() {
            index.entry(block.hash).or_default().push((file_index, block_index));
        }
    }
    index
}

/// Records one matching pair of block locations, keyed by
/// `(file_a, file_b, delta)` where `delta = block_index_b - block_index_a`
/// — grouping by delta lets consecutive matching blocks be recognized as
/// one contiguous run. `a`/`b` are order-independent (the smaller location
/// is treated as `a`); a location never matches itself.
fn record_pair(
    matches: &mut BTreeMap<(usize, usize, isize), BTreeSet<usize>>,
    a: (usize, usize),
    b: (usize, usize),
) {
    if a == b {
        return;
    }
    let (file_a, idx_a) = a;
    let (file_b, idx_b) = b;
    let delta = idx_b as isize - idx_a as isize;
    matches.entry((file_a, file_b, delta)).or_default().insert(idx_b);
}

fn group_matches_by_delta(
    index: &HashMap<u64, Vec<(usize, usize)>>,
) -> BTreeMap<(usize, usize, isize), BTreeSet<usize>> {
    let mut matches = BTreeMap::new();
    for locations in index.values() {
        if locations.len() < 2 {
            continue;
        }
        for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let (a, b) =
                    if locations[i] <= locations[j] { (locations[i], locations[j]) } else { (locations[j], locations[i]) };
                record_pair(&mut matches, a, b);
            }
        }
    }
    matches
}

/// Collapses a sorted set of block-index "starts" into maximal runs of
/// consecutive indices, each returned as an inclusive `(run_start, run_end)`.
fn consecutive_runs(starts: &BTreeSet<usize>) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut previous: Option<usize> = None;
    for &start in starts {
        match previous {
            Some(prev) if start == prev + 1 => {}
            Some(prev) => {
                runs.push((
                    run_start.expect("run_start is set on the first iteration and only cleared by this arm, which reads it first"),
                    prev,
                ));
                run_start = Some(start);
            }
            None => run_start = Some(start),
        }
        previous = Some(start);
    }
    if let (Some(rs), Some(prev)) = (run_start, previous) {
        runs.push((rs, prev));
    }
    runs
}

/// Builds the `DuplicateBlock` for one matched run and records every line
/// it covers into `duplicated`.
#[allow(clippy::too_many_arguments)]
fn record_duplicate_run(
    files: &[TokenizedFile],
    per_file_blocks: &[Vec<Block>],
    per_file_statements: &[Vec<Statement>],
    file_a: usize,
    file_b: usize,
    delta: isize,
    run_start: usize,
    run_end: usize,
    duplicated: &mut BTreeSet<(usize, u32)>,
) -> DuplicateBlock {
    let blocks_a = &per_file_blocks[file_a];
    let blocks_b = &per_file_blocks[file_b];
    let a_start = (run_start as isize - delta) as usize;
    let a_end = (run_end as isize - delta) as usize;
    let block_a = blocks_a[a_start];
    let block_a_end = blocks_a[a_end];
    let block_b = blocks_b[run_start];
    let block_b_end = blocks_b[run_end];

    let stmts_a = &per_file_statements[file_a];
    let stmts_b = &per_file_statements[file_b];
    for stmt in &stmts_a[block_a.stmt_start..=block_a_end.stmt_end] {
        duplicated.insert((file_a, stmt.line_number));
    }
    for stmt in &stmts_b[block_b.stmt_start..=block_b_end.stmt_end] {
        duplicated.insert((file_b, stmt.line_number));
    }

    let first = BlockRef {
        file: files[file_a].path.clone(),
        start_line: stmts_a[block_a.stmt_start].line_number,
        end_line: stmts_a[block_a_end.stmt_end].line_number,
    };
    let second = BlockRef {
        file: files[file_b].path.clone(),
        start_line: stmts_b[block_b.stmt_start].line_number,
        end_line: stmts_b[block_b_end.stmt_end].line_number,
    };
    let lines = (second.end_line - second.start_line + 1) as usize;
    DuplicateBlock { first, second, lines }
}

pub fn find_duplicates(files: &[TokenizedFile], config: DuplicationConfig) -> DuplicationReport {
    let block_size = config.block_size.max(2);
    let per_file_statements: Vec<Vec<Statement>> =
        files.iter().map(|f| collapse_repeats(statements(f))).collect();
    let per_file_blocks: Vec<Vec<Block>> =
        per_file_statements.iter().map(|s| chunk_blocks(s, block_size)).collect();

    let index = build_hash_index(&per_file_blocks);
    let matches = group_matches_by_delta(&index);

    let mut blocks_out = Vec::new();
    let mut duplicated: BTreeSet<(usize, u32)> = BTreeSet::new();
    for ((file_a, file_b, delta), starts) in matches {
        for (run_start, run_end) in consecutive_runs(&starts) {
            blocks_out.push(record_duplicate_run(
                files,
                &per_file_blocks,
                &per_file_statements,
                file_a,
                file_b,
                delta,
                run_start,
                run_end,
                &mut duplicated,
            ));
        }
    }

    DuplicationReport { blocks: blocks_out, duplicated_lines: duplicated.len() }
}

#[cfg(test)]
mod tests {
    use vord_ast::LanguageIdentifier;

    use super::*;

    fn file(path: &str, content: &str) -> TokenizedFile {
        let source = SourceFile::new(path, content, LanguageIdentifier::rust()).unwrap();
        TokenizedFile { path: source.path().to_string(), lines: fallback_tokenize(&source) }
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

        let report = find_duplicates(&files, DuplicationConfig { block_size: 5 });
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
        let report = find_duplicates(&files, DuplicationConfig { block_size: 5 });
        assert!(report.blocks.is_empty());
        assert_eq!(report.duplicated_lines, 0);
    }

    #[test]
    fn short_files_are_ignored() {
        let files = [file("a.rs", "let x = 1;\n"), file("b.rs", "let x = 1;\n")];
        let report = find_duplicates(&files, DuplicationConfig::default());
        assert!(report.blocks.is_empty());
    }

    #[test]
    fn repeated_identical_statements_do_not_inflate_a_match_on_their_own() {
        // Fifty identical lines in both files: BlockChunker's repetition
        // filter collapses each run to first+last, so this alone must not
        // register as an (identical-content) duplicate the way a naive
        // per-line/window hash would.
        let repeated: String = (0..50).map(|_| "    noop();\n".to_string()).collect();
        let a = format!("fn a() {{\n{repeated}}}\n");
        let b = format!("fn b() {{\n{repeated}}}\n");
        let files = [file("a.rs", &a), file("b.rs", &b)];
        let report = find_duplicates(&files, DuplicationConfig::default());
        assert!(report.blocks.is_empty(), "{:?}", report.blocks);
    }

    #[test]
    fn three_way_duplicate_is_reported_pairwise_across_all_files() {
        let shared: String = (0..6).map(|i| format!("    acc += items[{i}];\n")).collect();
        let files = [
            file("a.rs", &format!("fn a() {{\n{shared}}}\n")),
            file("b.rs", &format!("fn b() {{\n{shared}}}\n")),
            file("c.rs", &format!("fn c() {{\n{shared}}}\n")),
        ];
        let report = find_duplicates(&files, DuplicationConfig { block_size: 5 });
        // a-b, a-c, b-c.
        assert_eq!(report.blocks.len(), 3);
    }

    #[test]
    fn tokenized_input_matches_statements_that_differ_only_in_literal_values() {
        // Simulates what a real per-language tokenizer (vord-treesitter-tokens)
        // produces: literal values collapsed to a shared placeholder, so two
        // statements differing only in a literal are the same "statement" for
        // duplication purposes — the fallback line-trim tokenizer cannot do
        // this, since it hashes the literal's own text.
        let body: Vec<(u32, String)> = (0..6)
            .map(|i| (i + 2, format!("total += weights [ {i} ] * LIT ;")))
            .collect();
        let a = TokenizedFile { path: "a.rs".into(), lines: body.clone() };
        let b = TokenizedFile { path: "b.rs".into(), lines: body };
        let report = find_duplicates(&[a, b], DuplicationConfig { block_size: 5 });
        assert_eq!(report.blocks.len(), 1);
        assert_eq!(report.blocks[0].lines, 6);
    }
}
