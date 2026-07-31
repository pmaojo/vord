// duplication_edge.rs — exercises the literal-density duplication filter
// on Rust code.
//
// Expected findings:
// - human_label/display_grade/short_desc match arms → NO duplication finding
//   (suppressed: lookup tables, high literal density)
// - validate_input_a/validate_input_b → YES duplication finding
//   (real copied logic, low literal density)
// - build_report_a/build_report_b → YES duplication finding
//   (identical body, no placeholders)

// ─── Lookup-table match statements (should be SUPPRESSED) ───────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Grade { A, B, C, D, F }

fn human_label(grade: Grade) -> &'static str {
    match grade {
        Grade::A => "Excellent",
        Grade::B => "Good",
        Grade::C => "Average",
        Grade::D => "Below Average",
        Grade::F => "Failing",
    }
}

fn display_grade(grade: Grade) -> &'static str {
    match grade {
        Grade::A => "A (90-100%)",
        Grade::B => "B (80-89%)",
        Grade::C => "C (70-79%)",
        Grade::D => "D (60-69%)",
        Grade::F => "F (< 60%)",
    }
}

fn short_desc(grade: Grade) -> &'static str {
    match grade {
        Grade::A => "top marks",
        Grade::B => "above par",
        Grade::C => "satisfactory",
        Grade::D => "needs work",
        Grade::F => "unsatisfactory",
    }
}

// ─── Real duplicated logic (should be FLAGGED) ──────────────────────────────

fn validate_input_a(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("input must not be empty".to_string());
    }
    let trimmed = raw.trim().to_string();
    if trimmed.len() < 3 {
        return Err("input must be at least 3 characters".to_string());
    }
    if trimmed.len() > 50 {
        return Err("input must be at most 50 characters".to_string());
    }
    if trimmed.contains('<') || trimmed.contains('>') {
        return Err("input contains angle brackets".to_string());
    }
    Ok(trimmed)
}

fn validate_input_b(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("input must not be empty".to_string());
    }
    let trimmed = raw.trim().to_string();
    if trimmed.len() < 3 {
        return Err("input must be at least 3 characters".to_string());
    }
    if trimmed.len() > 50 {
        return Err("input must be at most 50 characters".to_string());
    }
    if trimmed.contains('<') || trimmed.contains('>') {
        return Err("input contains angle brackets".to_string());
    }
    Ok(trimmed)
}

// ─── Identical-structure duplication with no placeholder tokens ─────────────

fn build_report_a(items: &[i32]) -> (i32, f64, i32, i32) {
    let sum: i32 = items.iter().sum();
    let avg = sum as f64 / items.len() as f64;
    let min = *items.iter().min().unwrap_or(&0);
    let max = *items.iter().max().unwrap_or(&0);
    (sum, avg, min, max)
}

fn build_report_b(items: &[i32]) -> (i32, f64, i32, i32) {
    let sum: i32 = items.iter().sum();
    let avg = sum as f64 / items.len() as f64;
    let min = *items.iter().min().unwrap_or(&0);
    let max = *items.iter().max().unwrap_or(&0);
    (sum, avg, min, max)
}

fn main() {
    let g = Grade::B;
    println!("{} / {}", human_label(g), display_grade(g));

    let _ = validate_input_a("hello");
    let _ = validate_input_b("world");

    println!("{:?}", build_report_a(&[1, 2, 3]));
}
