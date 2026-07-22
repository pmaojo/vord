//! Cobertura XML coverage-report parsing (inbound adapter).

use yunq_rules_engine::CoverageSummary;

#[derive(Debug, thiserror::Error)]
pub enum CoberturaError {
    #[error("empty or invalid Cobertura XML input")]
    Empty,
    #[error("malformed Cobertura line: {0}")]
    Malformed(String),
}

pub fn parse_cobertura(content: &str) -> Result<CoverageSummary, CoberturaError> {
    let mut summary = CoverageSummary::default();
    let mut covered = 0usize;
    let mut total = 0usize;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<line ") || trimmed.starts_with("<line ") {
            if let (Some(hits_str), Some(_num_str)) = (extract_attr(trimmed, "hits"), extract_attr(trimmed, "number")) {
                let hits: usize = hits_str.parse().unwrap_or(0);
                total += 1;
                if hits > 0 {
                    covered += 1;
                }
            }
        } else if trimmed.contains("<coverage ") {
            if let (Some(c_str), Some(v_str)) = (extract_attr(trimmed, "lines-covered"), extract_attr(trimmed, "lines-valid")) {
                if let (Ok(c), Ok(v)) = (c_str.parse::<usize>(), v_str.parse::<usize>()) {
                    if v > 0 {
                        summary.add(c, v).map_err(|e| CoberturaError::Malformed(e.to_string()))?;
                        return Ok(summary);
                    }
                }
            }
        }
    }

    if total == 0 {
        return Err(CoberturaError::Empty);
    }

    summary.add(covered, total).map_err(|e| CoberturaError::Malformed(e.to_string()))?;
    Ok(summary)
}

fn extract_attr<'a>(line: &'a str, attr: &str) -> Option<&'a str> {
    let key = format!("{attr}=\"");
    let start = line.find(&key)? + key.len();
    let end = line[start..].find('"')? + start;
    Some(&line[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cobertura_line_tags() {
        let xml = r#"<?xml version="1.0"?>
<coverage line-rate="0.75">
  <packages>
    <package name="main">
      <classes>
        <class name="App" filename="App.java">
          <lines>
            <line number="1" hits="3"/>
            <line number="2" hits="0"/>
            <line number="3" hits="1"/>
            <line number="4" hits="0"/>
          </lines>
        </class>
      </classes>
    </package>
  </packages>
</coverage>"#;
        let summary = parse_cobertura(xml).unwrap();
        assert_eq!(summary.covered_lines(), 2);
        assert_eq!(summary.coverable_lines(), 4);
    }
}
