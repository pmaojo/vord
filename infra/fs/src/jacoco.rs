//! JaCoCo XML coverage-report parsing (inbound adapter).

use yunq_rules_engine::CoverageSummary;

#[derive(Debug, thiserror::Error)]
pub enum JacocoError {
    #[error("no line counters found in JaCoCo XML input")]
    Empty,
    #[error("malformed JaCoCo line: {0}")]
    Malformed(String),
}

pub fn parse_jacoco(content: &str) -> Result<CoverageSummary, JacocoError> {
    let mut summary = CoverageSummary::default();
    let mut total_covered = 0usize;
    let mut total_missed = 0usize;
    let mut found = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("type=\"LINE\"") || trimmed.contains("type='LINE'") {
            let missed = extract_attr(trimmed, "missed").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            let covered = extract_attr(trimmed, "covered").and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
            total_missed += missed;
            total_covered += covered;
            found = true;
        }
    }

    if !found {
        return Err(JacocoError::Empty);
    }

    let total = total_covered + total_missed;
    summary.add(total_covered, total).map_err(|e| JacocoError::Malformed(e.to_string()))?;
    Ok(summary)
}

fn extract_attr<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let key1 = format!("{attr}=\"");
    if let Some(start_idx) = line.find(&key1) {
        let start = start_idx + key1.len();
        let end = line[start..].find('"')? + start;
        return Some(&line[start..end]);
    }
    let key2 = format!("{attr}='");
    if let Some(start_idx) = line.find(&key2) {
        let start = start_idx + key2.len();
        let end = line[start..].find('\'')? + start;
        return Some(&line[start..end]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_jacoco_counter_tags() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<report name="yunq">
  <package name="com/example">
    <class name="com/example/Service">
      <counter type="INSTRUCTION" missed="20" covered="80"/>
      <counter type="LINE" missed="5" covered="15"/>
    </class>
  </package>
  <counter type="LINE" missed="10" covered="40"/>
</report>"#;
        let summary = parse_jacoco(xml).unwrap();
        assert_eq!(summary.covered_lines(), 55);
        assert_eq!(summary.coverable_lines(), 70);
    }
}
