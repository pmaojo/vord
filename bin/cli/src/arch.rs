//! `yunq arch` — the interactive architecture viewer (roadmap item: auto-
//! detect and render a project's component graph without any config).
//!
//! Reuses `core/import-graph`'s already-shipped analysis (file-level import
//! edges collapsed to components via path topology, Martin's Ca/Ce/I/A/D
//! component metrics, Tarjan cycle detection) and renders it four ways:
//! a text summary, a Mermaid `flowchart`, raw JSON, or a **self-contained
//! interactive HTML viewer** (embedded data + a tiny force-directed canvas
//! renderer — no CDN, no build step, works offline).

use std::collections::BTreeMap;
use std::path::Path;

use yunq_import_graph::{ImportGraph, TypeCensus, component_metrics, component_of};
use yunq_rules_engine::AstParser;

pub struct ArchSummary {
    pub files: usize,
    pub components: BTreeMap<String, yunq_import_graph::ComponentMetrics>,
    pub edges: Vec<(String, String)>,
    pub cycles: Vec<Vec<String>>,
}

/// Parses every import-graph-supported file under `root` (TS/JS/TSX/JSX,
/// Python, Rust, Go — the four languages `ImportGraph` resolves), builds the
/// component graph, and folds per-component type counts into the census so
/// `A`/`D` are real. Files that fail to parse are skipped silently (a parse
/// error is an analysis signal, not an architecture one).
pub fn analyze(root: &Path) -> anyhow::Result<ArchSummary> {
    let sources = yunq_infra_fs::collect_sources_scoped(root, &[], &[])?;
    let rust_crates = yunq_infra_fs::discover_rust_crates(root);

    let mut parsed: Vec<(yunq_ast::SourceFile, yunq_ast::AstNode)> = Vec::new();
    let mut census: BTreeMap<String, TypeCensus> = BTreeMap::new();

    for file in &sources {
        let parser: Option<Box<dyn AstParser>> = match file.language().as_str() {
            "typescript" => Some(Box::new(yunq_parser_typescript::TypeScriptParser::new())),
            "rust" => Some(Box::new(yunq_parser_rust::RustParser::new())),
            "python" => Some(Box::new(yunq_parser_python::PythonParser::new())),
            "go" => Some(Box::new(yunq_parser_go::GoParser::new())),
            _ => None,
        };
        let Some(parser) = parser else { continue };
        let Ok(ast) = parser.parse(file) else { continue };
        census
            .entry(component_of(file.path()))
            .or_default()
            .add(type_census(&ast));
        parsed.push((file.clone(), ast));
    }

    let views: Vec<(&str, &yunq_ast::AstNode)> =
        parsed.iter().map(|(f, a)| (f.path(), a)).collect();
    let graph = ImportGraph::build_with_rust_crates(&views, &rust_crates);
    let components = component_metrics(&graph, &census);
    let cycles = graph.cycles();
    let edges: Vec<(String, String)> = graph.component_edges().into_iter().collect();

    Ok(ArchSummary {
        files: parsed.len(),
        components,
        edges,
        cycles,
    })
}

/// Per-file type census for the abstractness metric: how many declared types
/// and how many of those are abstractions. Kept deliberately small — `A`
/// needs to distinguish "mostly interfaces/traits" from "mostly concrete
/// classes/structs", nothing finer.
fn type_census(ast: &yunq_ast::AstNode) -> TypeCensus {
    let mut abstractions = 0usize;
    let mut total = 0usize;
    for node in ast.descendants() {
        let yunq_ast::NodeKind::Other(kind) = node.kind() else { continue };
        let kind = kind.as_ref();
        let is_type = matches!(
            kind,
            "class_declaration"
                | "interface_declaration"
                | "type_alias_declaration"
                | "abstract_class_declaration"
                | "struct_item"
                | "enum_item"
                | "trait_item"
                | "struct_declaration"
                | "interface_type"
                | "type_declaration"
        );
        if !is_type {
            continue;
        }
        total += 1;
        if matches!(
            kind,
            "interface_declaration" | "abstract_class_declaration" | "trait_item" | "interface_type"
        ) {
            abstractions += 1;
        }
    }
    TypeCensus::new(total, abstractions)
}

pub fn render_text(summary: &ArchSummary) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Architecture: {} file(s), {} component(s), {} edge(s), {} cycle(s)\n",
        summary.files,
        summary.components.len(),
        summary.edges.len(),
        summary.cycles.len()
    ));
    out.push_str("\nComponent metrics (Martin):\n");
    out.push_str("  component                        Ca  Ce     I     A     D\n");
    for (name, m) in &summary.components {
        out.push_str(&format!(
            "  {:<32} {:>3} {:>3}  {:>5.2} {:>5.2} {:>5.2}\n",
            name,
            m.afferent,
            m.efferent,
            m.instability(),
            m.abstractness(),
            m.distance_from_main_sequence()
        ));
    }
    if !summary.cycles.is_empty() {
        out.push_str("\nDependency cycles:\n");
        for cycle in &summary.cycles {
            out.push_str(&format!("  {}\n", cycle.join(" -> ")));
        }
    }
    out
}

/// A Mermaid `flowchart LR`: components as nodes, imports as directed edges,
/// cycle members highlighted. Ids are sanitized (`/` and `-` are not valid
/// bare Mermaid ids) and the real name kept in the node label.
pub fn render_mermaid(summary: &ArchSummary) -> String {
    let mut out = String::from("flowchart LR\n");
    let id = |name: &str| {
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
            .collect::<String>()
    };
    let in_cycle: std::collections::BTreeSet<&str> = summary
        .cycles
        .iter()
        .flatten()
        .map(String::as_str)
        .collect();
    for name in summary.components.keys() {
        let style = if in_cycle.contains(name.as_str()) {
            ":::cycle"
        } else {
            ""
        };
        out.push_str(&format!("  {}(\"{}\"){}\n", id(name), name, style));
    }
    for (from, to) in &summary.edges {
        out.push_str(&format!("  {} --> {}\n", id(from), id(to)));
    }
    out.push_str("  classDef cycle fill:#fde2e2,stroke:#c0392b,stroke-width:2px;\n");
    out
}

pub fn render_json(summary: &ArchSummary) -> anyhow::Result<String> {
    let components: Vec<serde_json::Value> = summary
        .components
        .values()
        .map(|m| {
            serde_json::json!({
                "component": m.component,
                "afferent": m.afferent,
                "efferent": m.efferent,
                "instability": m.instability(),
                "abstractness": m.abstractness(),
                "distance_from_main_sequence": m.distance_from_main_sequence(),
                "in_zone_of_pain": m.in_zone_of_pain(),
            })
        })
        .collect();
    let json = serde_json::json!({
        "files": summary.files,
        "components": components,
        "edges": summary.edges,
        "cycles": summary.cycles,
    });
    Ok(serde_json::to_string_pretty(&json)?)
}

/// A fully self-contained interactive viewer: the JSON graph is embedded in
/// the page and rendered with a small force-directed layout on `<canvas>`
/// (Coulomb repulsion + edge springs + damping). Nodes are colored by
/// cycle membership and sized by coupling; clicking a node shows its Martin
/// metrics. No network access, no build step.
pub fn render_html(summary: &ArchSummary) -> anyhow::Result<String> {
    // A `</script>` sequence inside a JSON string value would terminate the
    // embedded <script> block; `\/` is the same string with an escaped
    // solidus (valid in both JSON and JS), so the page always parses.
    let data = render_json(summary)?.replace("</script>", "<\\/script>");
    Ok(format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>yunq arch — component architecture</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; }}
  header {{ padding: 16px 24px; display: flex; gap: 16px; align-items: baseline; flex-wrap: wrap; border-bottom: 1px solid #1e293b; }}
  header h1 {{ font-size: 18px; margin: 0; }}
  header .stats {{ color: #94a3b8; font-size: 13px; }}
  header .legend {{ margin-left: auto; font-size: 12px; display: flex; gap: 14px; align-items: center; }}
  .dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; vertical-align: middle; }}
  .dot.cycle {{ background: #ef4444; }}
  .dot.clean {{ background: #22c55e; }}
  main {{ display: flex; min-height: calc(100vh - 57px); }}
  #graph {{ flex: 1; height: calc(100vh - 57px); }}
  aside {{ width: 320px; border-left: 1px solid #1e293b; padding: 16px; overflow-y: auto; font-size: 13px; }}
  aside h2 {{ font-size: 14px; margin: 0 0 12px; color: #f8fafc; }}
  aside table {{ width: 100%; border-collapse: collapse; }}
  aside td, aside th {{ padding: 4px 6px; text-align: left; border-bottom: 1px solid #1e293b; }}
  aside th {{ color: #94a3b8; font-weight: 500; }}
  #hint {{ color: #64748b; font-size: 12px; margin-top: 12px; }}
  canvas {{ display: block; width: 100%; height: 100%; }}
</style>
</head>
<body>
<header>
  <h1>yunq arch</h1>
  <span class="stats" id="stats"></span>
  <span class="legend">
    <span><span class="dot clean"></span>clean component</span>
    <span><span class="dot cycle"></span>in dependency cycle</span>
  </span>
</header>
<main>
  <div id="graph"><canvas id="cv"></canvas></div>
  <aside><h2>Component metrics</h2><div id="detail"><p>Click a node.</p></div><p id="hint">Force-directed layout: nodes repel, edges pull. Red = member of a dependency cycle.</p></aside>
</main>
<script>
const DATA = {data};
const cv = document.getElementById('cv');
const ctx = cv.getContext('2d');
const W = () => cv.clientWidth, H = () => cv.clientHeight;
function resize() {{ const dpr = window.devicePixelRatio || 1; cv.width = W() * dpr; cv.height = H() * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); }}
window.addEventListener('resize', resize);
const cycleMembers = new Set(DATA.cycles.flat());
const nodes = DATA.components.map(c => ({{
  id: c.component, m: c, x: Math.random()*400, y: Math.random()*400, vx: 0, vy: 0,
  r: 14 + Math.min(18, (c.afferent + c.efferent) * 4),
  cyc: cycleMembers.has(c.component)
}}));
const byId = new Map(nodes.map(n => [n.id, n]));
const edges = DATA.edges.map(([a, b]) => [byId.get(a), byId.get(b)]).filter(e => e[0] && e[1]);
function tick() {{
  const K = 0.06, C = 6000, L = 110, DAMP = 0.85;
  for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {{
    const a = nodes[i], b = nodes[j];
    let dx = a.x - b.x, dy = a.y - b.y;
    const d2 = dx*dx + dy*dy + 1, d = Math.sqrt(d2);
    let f = C / d2;
    dx /= d; dy /= d;
    a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
  }}
  for (const [a, b] of edges) {{
    let dx = b.x - a.x, dy = b.y - a.y;
    const d = Math.sqrt(dx*dx + dy*dy) + 0.001;
    let f = (d - L) * K;
    dx /= d; dy /= d;
    a.vx += dx * f; a.vy += dy * f; b.vx -= dx * f; b.vy -= dy * f;
  }}
  const cx = W()/2, cy = H()/2;
  for (const n of nodes) {{
    n.vx += (cx - n.x) * 0.001; n.vy += (cy - n.y) * 0.001;
    n.vx *= DAMP; n.vy *= DAMP;
    n.x += n.vx; n.y += n.vy;
    n.x = Math.max(20, Math.min(W() - 20, n.x));
    n.y = Math.max(20, Math.min(H() - 20, n.y));
  }}
}}
function draw() {{
  ctx.clearRect(0, 0, W(), H());
  ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue('color-scheme').includes('dark') ? 'rgba(148,163,184,0.35)' : 'rgba(30,41,59,0.35)';
  for (const [a, b] of edges) {{
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
  }}
  for (const n of nodes) {{
    ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
    ctx.fillStyle = n.cyc ? '#ef4444' : '#22c55e';
    ctx.globalAlpha = 0.85; ctx.fill(); ctx.globalAlpha = 1;
    ctx.fillStyle = '#f8fafc';
    ctx.font = (n.cyc ? '700 ' : '') + '11px sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    const label = n.id.split('/').pop().split('.').shift();
    ctx.fillText(label, n.x, n.y + n.r + 12);
  }}
}}
function hit(x, y) {{
  for (let i = nodes.length - 1; i >= 0; i--) {{
    const n = nodes[i]; const dx = n.x - x, dy = n.y - y;
    if (dx*dx + dy*dy <= (n.r + 6) * (n.r + 6)) return n;
  }}
  return null;
}}
cv.addEventListener('click', e => {{
  const r = cv.getBoundingClientRect();
  const n = hit(e.clientX - r.left, e.clientY - r.top);
  if (!n) return;
  const m = n.m;
  document.getElementById('detail').innerHTML =
    '<table><tr><th>Component</th><td>' + n.id.replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</td></tr>' +
    '<tr><th>Ca (afferent)</th><td>' + m.afferent + '</td></tr>' +
    '<tr><th>Ce (efferent)</th><td>' + m.efferent + '</td></tr>' +
    '<tr><th>Instability I</th><td>' + m.instability.toFixed(2) + '</td></tr>' +
    '<tr><th>Abstractness A</th><td>' + m.abstractness.toFixed(2) + '</td></tr>' +
    '<tr><th>Distance D</th><td>' + m.distance_from_main_sequence.toFixed(2) + '</td></tr>' +
    '<tr><th>Zone of pain</th><td>' + (m.in_zone_of_pain ? 'yes' : 'no') + '</td></tr></table>';
}});
document.getElementById('stats').textContent =
  DATA.files + ' files · ' + DATA.components.length + ' components · ' + DATA.edges.length + ' edges · ' + DATA.cycles.length + ' cycles';
resize();
for (let i = 0; i < 700; i++) tick();
requestAnimationFrame(function loop() {{ draw(); requestAnimationFrame(loop); }});
</script>
</body>
</html>"#))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yunq_ast::{LanguageIdentifier, SourceFile};

    fn parse_ts(path: &str, code: &str) -> (SourceFile, yunq_ast::AstNode) {
        let file = SourceFile::new(path, code, LanguageIdentifier::typescript()).unwrap();
        let ast = yunq_parser_typescript::TypeScriptParser::new()
            .parse(&file)
            .unwrap();
        (file, ast)
    }

    #[test]
    fn census_counts_interfaces_as_abstractions() {
        let (_, ast) = parse_ts(
            "a.ts",
            "export interface Contract {}\nexport class Impl implements Contract {}\nexport type Alias = number;\n",
        );
        let census = type_census(&ast);
        assert_eq!(census.total, 3);
        assert_eq!(census.abstractions, 1);
    }

    #[test]
    fn mermaid_renders_every_component_and_edge() {
        // Hand-built summary (deterministic, no import resolution needed):
        // the renderer's contract is "one node per component, one arrow per
        // edge" — resolution is `ImportGraph`'s job, covered elsewhere.
        let metrics = BTreeMap::from([
            (
                "core/a".to_string(),
                yunq_import_graph::ComponentMetrics {
                    component: "core/a".into(),
                    afferent: 1,
                    efferent: 0,
                    census: TypeCensus::new(1, 0),
                },
            ),
            (
                "infra/fs".to_string(),
                yunq_import_graph::ComponentMetrics {
                    component: "infra/fs".into(),
                    afferent: 0,
                    efferent: 1,
                    census: TypeCensus::new(1, 0),
                },
            ),
        ]);
        let summary = ArchSummary {
            files: 2,
            components: metrics,
            edges: vec![("core/a".to_string(), "infra/fs".to_string())],
            cycles: vec![vec!["infra/fs".to_string()]],
        };
        let mermaid = render_mermaid(&summary);
        assert!(mermaid.contains("flowchart LR"));
        assert!(mermaid.contains("core_a"));
        assert!(mermaid.contains("infra_fs"));
        assert!(mermaid.contains("-->"));
        assert!(mermaid.contains("classDef cycle"));
    }

    #[test]
    fn html_embeds_the_graph_json() {
        let summary = ArchSummary {
            files: 0,
            components: BTreeMap::new(),
            edges: vec![],
            cycles: vec![],
        };
        let html = render_html(&summary).unwrap();
        assert!(html.contains("<canvas"));
        assert!(html.contains("\"components\": []"));
    }
}
