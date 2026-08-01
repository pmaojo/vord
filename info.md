¡Perfecto! Aquí tienes la versión **ampliada y con todos los ejemplos en Rust**, incluyendo **todos los algoritmos** de análisis de código con Tree-sitter:

***

# Compendio Completo de Algoritmos de Análisis de Código con Tree-sitter en Rust

## 0. Configuración Base con Tree-sitter

```rust
// Cargo.toml
[dependencies]
tree-sitter = "0.24"
tree-sitter-rust = "0.23"
tree-sitter-typescript = "0.23"
tree-sitter-python = "0.23"
tree-sitter-cpp = "0.23"
```

```rust
// src/parser.rs
use tree_sitter::{Parser, Tree, Language, Node};

pub struct CodeAnalyzer {
    parser: Parser,
}

impl CodeAnalyzer {
    pub fn new(language: Language) -> Self {
        let mut parser = Parser::new();
        parser.set_language(language).expect("Error loading grammar");
        Self { parser }
    }

    pub fn parse(&mut self, source_code: &str) -> Tree {
        self.parser.parse(source_code, None).unwrap()
    }

    pub fn parse_with_old_tree(&mut self, source_code: &str, old_tree: &Tree) -> Tree {
        self.parser.parse(source_code, Some(old_tree)).unwrap()
    }
}
```

***

## 1. Métricas Estructurales

### 1.1. **Complejidad Ciclomática (McCabe, 1976)**

**Fórmulas:**

\[
M = E - N + 2P
\]

\[
M = 1 + \sum_{i=1}^{k} \text{decisiones}_i
\]

\[
M = P + 1 \quad \text{(nodos predicados)}
\]

**Implementación en Rust:**

```rust
// src/cyclomatic_complexity.rs
use tree_sitter::{Tree, Node};

pub struct CyclomaticComplexity {
    pub complexity: u32,
    pub decisions: Vec<Decision>,
}

pub struct Decision {
    pub kind: String,
    pub line: u32,
    pub column: u32,
}

pub fn calculate_cyclomatic_complexity(tree: &Tree) -> CyclomaticComplexity {
    let mut complexity = 1; // Base
    let mut decisions = Vec::new();

    // Nodos de decisión en múltiples lenguajes
    let decision_nodes = [
        "if_statement", "if",
        "while_statement", "while",
        "for_statement", "for",
        "for_in_statement",
        "switch_case", "case",
        "catch_clause", "catch",
        "conditional_expression", // ternario ?:
        "binary_expression",      // && ||
        "try_statement",
        "finally_clause",
    ];

    fn traverse(node: Node, complexity: &mut u32, decisions: &mut Vec<Decision>) {
        if decision_nodes.contains(&node.kind()) {
            *complexity += 1;
            decisions.push(Decision {
                kind: node.kind().to_string(),
                line: node.start_position().row as u32,
                column: node.start_position().column as u32,
            });
        }

        // Operadores lógicos && y ||
        if node.kind() == "binary_expression" {
            let operator = node.child_by_field_name("operator");
            if let Some(op) = operator {
                if op.kind() == "&&" || op.kind() == "||" || op.kind() == "and" || op.kind() == "or" {
                    *complexity += 1;
                }
            }
        }

        // Operador ternario
        if node.kind() == "conditional_expression" || node.kind() == "ternary_expression" {
            *complexity += 1;
        }

        // Recorrer hijos
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                traverse(child, complexity, decisions);
            }
        }
    }

    traverse(tree.root_node(), &mut complexity, &mut decisions);

    CyclomaticComplexity { complexity, decisions }
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_simple_if() {
        let source = r#"
            fn test() {
                if x > 5 {
                    println!("greater");
                }
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);
        let result = calculate_cyclomatic_complexity(&tree);
        
        assert_eq!(result.complexity, 2); // 1 base + 1 if
    }

    #[test]
    fn test_complex_function() {
        let source = r#"
            fn process(x: i32, y: i32) -> i32 {
                if x > 0 && y > 0 {
                    for i in 0..x {
                        if i % 2 == 0 {
                            println!("even");
                        }
                    }
                } else if x < 0 {
                    println!("negative");
                }
                x + y
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);
        let result = calculate_cyclomatic_complexity(&tree);
        
        // 1 base + 1 if + 1 && + 1 for + 1 if + 1 else if = 6
        assert_eq!(result.complexity, 6);
    }
}
```

**Interpretación:**

| Rango | Nivel de Riesgo | Acción |
|-------|----------------|--------|
| 1-10 | Bajo | Código mantenible |
| 11-20 | Moderado | Considerar refactorización |
| 21-50 | Alto | Refactorizar urgentemente |
| >50 | Crítico | No testeable, reescribir |

***

### 1.2. **Métricas de Halstead (Software Science, 1977)**

**Fórmulas:**

**Vocabulario:**
\[
n = n_1 + n_2
\]

**Longitud:**
\[
N = N_1 + N_2
\]

**Volumen:**
\[
V = N \times \log_2(n)
\]

**Dificultad:**
\[
D = \frac{n_1}{2} \times \frac{N_2}{n_2}
\]

**Esfuerzo:**
\[
E = D \times V
\]

**Tiempo de implementación:**
\[
T = \frac{E}{18} \quad \text{(segundos)}
\]

**Bugs estimados:**
\[
B = \frac{V}{3000}
\]

**Nivel de abstracción:**
\[
L = \frac{1}{D}
\]

**Contenido de información:**
\[
I = V \times L
\]

**Implementación en Rust:**

```rust
// src/halstead_metrics.rs
use tree_sitter::{Tree, Node};
use std::collections::{HashMap, HashSet};
use std::f64;

pub struct HalsteadMetrics {
    // Contadores
    pub n1: u32, // operadores únicos
    pub n2: u32, // operandos únicos
    pub N1: u32, // total operadores
    pub N2: u32, // total operandos
    
    // Métricas derivadas
    pub n: u32,      // vocabulario
    pub N: u32,      // longitud
    pub V: f64,      // volumen
    pub D: f64,      // dificultad
    pub E: f64,      // esfuerzo
    pub T: f64,      // tiempo
    pub B: f64,      // bugs estimados
    pub L: f64,      // nivel
    pub I: f64,      // contenido información
}

pub struct HalsteadCollector {
    operators: HashMap<String, u32>,
    operands: HashMap<String, u32>,
}

impl HalsteadCollector {
    pub fn new() -> Self {
        Self {
            operators: HashMap::new(),
            operands: HashMap::new(),
        }
    }

    pub fn collect(&mut self, tree: &Tree, language: &str) {
        self.traverse(tree.root_node(), language);
    }

    fn traverse(&mut self, node: Node, language: &str) {
        // Clasificar nodo como operador u operando
        if self.is_operator(node, language) {
            let text = node.kind().to_string();
            *self.operators.entry(text).or_insert(0) += 1;
        } else if self.is_operand(node, language) {
            let text = node.kind().to_string();
            *self.operands.entry(text).or_insert(0) += 1;
        }

        // Recorrer hijos
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.traverse(child, language);
            }
        }
    }

    fn is_operator(&self, node: Node, language: &str) -> bool {
        let operators = match language {
            "rust" => [
                "assignment_expression", "binary_expression", "unary_expression",
                "compound_assignment_expr", "range_expression", "lambda_expression",
                "call_expression", "index_expression", "field_expression",
                "as_expression", "try_expression", "await_expression",
                "+", "-", "*", "/", "%", "&&", "||", "==", "!=", "<", ">", "<=", ">=",
                "!", "&", "|", "^", "<<", ">>", "=", "+=", "-=", "*=", "/=",
            ],
            "typescript" => [
                "assignment_expression", "binary_expression", "unary_expression",
                "update_expression", "yield_expression", "type_assertion",
                "new_expression", "class_expression", "function_expression",
            ],
            _ => return false,
        };

        operators.contains(&node.kind())
    }

    fn is_operand(&self, node: Node, language: &str) -> bool {
        let operands = match language {
            "rust" => [
                "identifier", "integer_literal", "float_literal", "string_literal",
                "char_literal", "boolean_literal", "self",
            ],
            "typescript" => [
                "identifier", "number", "string", "template_string",
                "true", "false", "null", "undefined", "this",
            ],
            _ => return false,
        };

        operands.contains(&node.kind())
    }

    pub fn calculate_metrics(&self) -> HalsteadMetrics {
        let n1 = self.operators.len() as u32;
        let n2 = self.operands.len() as u32;
        let N1: u32 = self.operators.values().sum();
        let N2: u32 = self.operands.values().sum();

        let n = n1 + n2;
        let N = N1 + N2;

        // Evitar log(0)
        let n_f64 = if n > 0 { n as f64 } else { 1.0 };
        let n2_f64 = if n2 > 0 { n2 as f64 } else { 1.0 };

        let V = (N as f64) * n_f64.log2();
        let D = (n1 as f64 / 2.0) * (N2 as f64 / n2_f64);
        let E = D * V;
        let T = E / 18.0;
        let B = V / 3000.0;
        let L = 1.0 / if D > 0.0 { D } else { 1.0 };
        let I = V * L;

        HalsteadMetrics {
            n1, n2, N1, N2,
            n, N, V, D, E, T, B, L, I,
        }
    }
}

pub fn calculate_halstead(tree: &Tree, language: &str) -> HalsteadMetrics {
    let mut collector = HalsteadCollector::new();
    collector.collect(tree, language);
    collector.calculate_metrics()
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_simple_function() {
        let source = r#"
            fn sum(a: i32, b: i32) -> i32 {
                a + b
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);
        let metrics = calculate_halstead(&tree, "rust");

        println!("n1 (operadores únicos): {}", metrics.n1);
        println!("n2 (operandos únicos): {}", metrics.n2);
        println!("N1 (total operadores): {}", metrics.N1);
        println!("N2 (total operandos): {}", metrics.N2);
        println!("Volumen: {:.2}", metrics.V);
        println!("Dificultad: {:.2}", metrics.D);
        println!("Esfuerzo: {:.2}", metrics.E);
        println!("Bugs estimados: {:.2}", metrics.B);
    }
}
```

***

### 1.3. **Métricas de Acoplamiento (Fan-in / Fan-out)**

**Fórmulas:**

**Fan-in:**
\[
\text{Fan-in}(M) = |\{C \mid C \text{ llama a } M\}|
\]

**Fan-out:**
\[
\text{Fan-out}(M) = |\{C \mid M \text{ llama a } C\}|
\]

**Inestabilidad:**
\[
I = \frac{\text{Fan-out}}{\text{Fan-in} + \text{Fan-out}}
\]

**Distancia desde la secuencia principal:**
\[
D = |A + I - 1|
\]

Donde \(A = \frac{\text{clases abstractas}}{\text{clases totales}}\)

**Implementación en Rust:**

```rust
// src/coupling_metrics.rs
use tree_sitter::{Tree, Node};
use std::collections::{HashMap, HashSet};

pub struct CouplingMetrics {
    pub fan_in: u32,
    pub fan_out: u32,
    pub instability: f64,
}

pub struct CallGraph {
    pub graph: HashMap<String, HashSet<String>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            graph: HashMap::new(),
        }
    }

    pub fn build(&mut self, tree: &Tree, language: &str) {
        let mut current_function: Option<String> = None;
        
        self.traverse(tree.root_node(), language, &mut current_function);
    }

    fn traverse(
        &mut self,
        node: Node,
        language: &str,
        current_function: &mut Option<String>,
    ) {
        // Detectar definición de función
        if self.is_function_definition(node, language) {
            if let Some(name) = self.get_function_name(&node, language) {
                *current_function = Some(name);
                self.graph.entry(name.clone()).or_insert_with(HashSet::new);
            }
        }

        // Detectar llamada a función
        if node.kind() == "call_expression" || node.kind() == "function_call" {
            if let Some(callee) = self.get_called_function(&node, language) {
                if let Some(caller) = current_function.clone() {
                    self.graph
                        .entry(caller)
                        .or_insert_with(HashSet::new)
                        .insert(callee);
                }
            }
        }

        // Recorrer hijos
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.traverse(child, language, current_function);
            }
        }
    }

    fn is_function_definition(&self, node: Node, language: &str) -> bool {
        match language {
            "rust" => node.kind() == "function_item" || node.kind() == "function",
            "typescript" => node.kind() == "function_declaration" || node.kind() == "method_definition",
            _ => false,
        }
    }

    fn get_function_name(&self, node: &Node, language: &str) -> Option<String> {
        match language {
            "rust" => {
                let name_node = node.child_by_field_name("name")?;
                Some(name_node.text().to_string())
            }
            "typescript" => {
                let name_node = node.child_by_field_name("name")?;
                Some(name_node.text().to_string())
            }
            _ => None,
        }
    }

    fn get_called_function(&self, node: &Node, language: &str) -> Option<String> {
        match language {
            "rust" => {
                let function_node = node.child_by_field_name("function")?;
                Some(function_node.text().to_string())
            }
            "typescript" => {
                let function_node = node.child_by_field_name("function")?;
                Some(function_node.text().to_string())
            }
            _ => None,
        }
    }
}

pub fn calculate_coupling_metrics(call_graph: &CallGraph) -> HashMap<String, CouplingMetrics> {
    let mut metrics = HashMap::new();

    // Calcular fan-out (salientes)
    for (caller, callees) in &call_graph.graph {
        let fan_out = callees.len() as u32;
        
        metrics.entry(caller.clone()).or_insert(CouplingMetrics {
            fan_in: 0,
            fan_out,
            instability: 0.0,
        });
    }

    // Calcular fan-in (entrantes)
    for (caller, callees) in &call_graph.graph {
        for callee in callees {
            let entry = metrics.entry(callee.clone()).or_insert(CouplingMetrics {
                fan_in: 0,
                fan_out: 0,
                instability: 0.0,
            });
            entry.fan_in += 1;
        }
    }

    // Calcular inestabilidad
    for metric in metrics.values_mut() {
        let total = metric.fan_in + metric.fan_out;
        metric.instability = if total > 0 {
            metric.fan_out as f64 / total as f64
        } else {
            0.0
        };
    }

    metrics
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_call_graph() {
        let source = r#"
            fn main() {
                helper();
                another();
            }

            fn helper() {
                println!("hello");
            }

            fn another() {
                helper();
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);

        let mut call_graph = CallGraph::new();
        call_graph.build(&tree, "rust");

        let metrics = calculate_coupling_metrics(&call_graph);

        // main tiene fan-out = 2 (helper, another)
        assert_eq!(metrics.get("main").unwrap().fan_out, 2);
        
        // helper tiene fan-in = 2 (main, another)
        assert_eq!(metrics.get("helper").unwrap().fan_in, 2);
    }
}
```

***

### 1.4. **Profundidad de Anidamiento (Nesting Depth)**

**Fórmulas:**

**Máxima:**
\[
\text{Nesting}_{\text{max}} = \max_{p \in \text{paths}}(\text{depth}(p))
\]

**Promedio:**
\[
\text{Nesting}_{\text{avg}} = \frac{1}{|P|} \sum_{p \in P} \text{depth}(p)
\]

**Suma:**
\[
\text{Nesting}_{\text{sum}} = \sum_{s \in \text{statements}} \text{depth}(s)
\]

**Implementación en Rust:**

```rust
// src/nesting_depth.rs
use tree_sitter::{Tree, Node};

pub struct NestingMetrics {
    pub max_depth: u32,
    pub avg_depth: f64,
    pub sum_depth: u32,
    pub statement_count: u32,
}

pub fn calculate_nesting_depth(tree: &Tree, language: &str) -> NestingMetrics {
    let mut max_depth = 0;
    let mut total_depth = 0;
    let mut statement_count = 0;

    fn traverse(node: Node, depth: u32, language: &str, metrics: &mut NestingMetricsAccumulator) {
        let nesting_nodes = match language {
            "rust" => [
                "if_expression", "if", "else",
                "while_expression", "while", "while_let_expression",
                "for_expression", "for",
                "match_expression", "match",
                "loop_expression", "loop",
                "if_let_expression",
            ],
            "typescript" => [
                "if_statement", "if", "else",
                "while_statement", "while",
                "for_statement", "for", "for_in", "for_of",
                "switch_statement", "switch",
                "try_statement", "try", "catch",
                "do_statement",
            ],
            _ => return,
        };

        // Incrementar profundidad si es nodo de anidamiento
        if nesting_nodes.contains(&node.kind()) {
            let new_depth = depth + 1;
            metrics.max_depth = metrics.max_depth.max(new_depth);
            metrics.total_depth += new_depth;
            metrics.statement_count += 1;
            
            // Recorrer hijos con nueva profundidad
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    traverse(child, new_depth, language, metrics);
                }
            }
        } else {
            // Recorrer hijos con misma profundidad
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    traverse(child, depth, language, metrics);
                }
            }
        }
    }

    struct NestingMetricsAccumulator {
        max_depth: u32,
        total_depth: u32,
        statement_count: u32,
    }

    let mut accumulator = NestingMetricsAccumulator {
        max_depth: 0,
        total_depth: 0,
        statement_count: 0,
    };

    traverse(tree.root_node(), 0, language, &mut accumulator);

    NestingMetrics {
        max_depth: accumulator.max_depth,
        avg_depth: if accumulator.statement_count > 0 {
            accumulator.total_depth as f64 / accumulator.statement_count as f64
        } else {
            0.0
        },
        sum_depth: accumulator.total_depth,
        statement_count: accumulator.statement_count,
    }
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_nested_ifs() {
        let source = r#"
            fn deeply_nested(x: i32, y: i32, z: i32) {
                if x > 0 {
                    if y > 0 {
                        if z > 0 {
                            println!("all positive");
                        }
                    }
                }
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);
        let metrics = calculate_nesting_depth(&tree, "rust");

        assert_eq!(metrics.max_depth, 3);
        println!("Profundidad máxima: {}", metrics.max_depth);
        println!("Profundidad promedio: {:.2}", metrics.avg_depth);
    }
}
```

***

## 2. Análisis de Flujo de Datos (Data Flow Analysis)

### 2.1. **Ecuaciones de Flujo de Datos (Bit-Vector Problems)**

**Ecuaciones:**

**Forward analysis:**
\[
\text{OUT}[B] = \text{GEN}[B] \cup (\text{IN}[B] - \text{KILL}[B])
\]

**Backward analysis (live variables):**
\[
\text{IN}[B] = \text{USE}[B] \cup (\text{OUT}[B] - \text{DEF}[B])
\]

**Función de transferencia:**
\[
f_B(X) = \text{GEN}[B] \cup (X - \text{KILL}[B])
\]

**Join (punto de entrada):**
\[
\text{IN}[B] = \bigcup_{P \in \text{pred}(B)} \text{OUT}[P]
\]

### 2.2. **Algoritmo de Punto Fijo (Worklist)**

**Implementación en Rust:**

```rust
// src/dataflow_analysis.rs
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicBlock {
    pub id: String,
    pub statements: Vec<String>,
    pub predecessors: Vec<String>,
    pub successors: Vec<String>,
}

pub struct CFG {
    pub blocks: Vec<BasicBlock>,
    pub entry: String,
    pub exit: String,
}

pub struct DataflowResult {
    pub in_facts: HashMap<String, HashSet<String>>,
    pub out_facts: HashMap<String, HashSet<String>>,
}

pub fn live_variable_analysis(cfg: &CFG) -> DataflowResult {
    let mut in_facts: HashMap<String, HashSet<String>> = HashMap::new();
    let mut out_facts: HashMap<String, HashSet<String>> = HashMap::new();

    // Inicializar
    for block in &cfg.blocks {
        in_facts.insert(block.id.clone(), HashSet::new());
        out_facts.insert(block.id.clone(), HashSet::new());
    }

    // Worklist
    let mut worklist: VecDeque<String> = cfg.blocks.iter().map(|b| b.id.clone()).collect();

    while let Some(block_id) = worklist.pop_front() {
        let block = cfg.blocks.iter().find(|b| b.id == block_id).unwrap();

        // OUT[B] = unión de IN de sucesores
        let mut out_vars = HashSet::new();
        for succ_id in &block.successors {
            if let Some(succ_in) = in_facts.get(succ_id) {
                out_vars.extend(succ_in.clone());
            }
        }

        // Calcular USE y DEF del bloque
        let use_vars = get_used_variables(block);
        let def_vars = get_defined_variables(block);

        // IN[B] = USE[B] ∪ (OUT[B] - DEF[B])
        let mut in_vars = use_vars;
        for v in &out_vars {
            if !def_vars.contains(v) {
                in_vars.insert(v.clone());
            }
        }

        // Si cambió, añadir predecesores al worklist
        let old_in = in_facts.get(&block_id).unwrap();
        if &in_vars != old_in {
            in_facts.insert(block_id.clone(), in_vars);
            out_facts.insert(block_id.clone(), out_vars);
            
            for pred_id in &block.predecessors {
                worklist.push_back(pred_id.clone());
            }
        }
    }

    DataflowResult { in_facts, out_facts }
}

fn get_used_variables(block: &BasicBlock) -> HashSet<String> {
    // Extraer variables usadas antes de ser definidas
    let mut used = HashSet::new();
    
    for stmt in &block.statements {
        // Análisis simple: identificar usos de variables
        // Ej: "x + y" → usa x, y
        let tokens: Vec<&str> = stmt.split_whitespace().collect();
        for token in tokens {
            if is_identifier(token) && !is_keyword(token) {
                used.insert(token.to_string());
            }
        }
    }
    
    used
}

fn get_defined_variables(block: &BasicBlock) -> HashSet<String> {
    // Extraer variables definidas
    let mut defined = HashSet::new();
    
    for stmt in &block.statements {
        // Análisis simple: identificar definiciones
        // Ej: "let x = 5" → define x
        if let Some(eq_pos) = stmt.find('=') {
            let left = stmt[..eq_pos].trim();
            if let Some(var_name) = extract_variable_name(left) {
                defined.insert(var_name);
            }
        }
    }
    
    defined
}

fn is_identifier(token: &str) -> bool {
    let keywords = ["let", "mut", "if", "else", "while", "for", "fn", "return"];
    !keywords.contains(&token) && token.chars().all(|c| c.is_alphanumeric() || c == '_')
}

fn is_keyword(token: &str) -> bool {
    let keywords = ["let", "mut", "if", "else", "while", "for", "fn", "return", "in"];
    keywords.contains(&token)
}

fn extract_variable_name(expr: &str) -> Option<String> {
    // Extraer nombre de variable de "let x" o "x"
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "let" {
        Some(parts [wippy](https://wippy.ai/es/lua/text/treesitter).to_string())
    } else if parts.len() == 1 {
        Some(parts[0].to_string())
    } else {
        None
    }
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_liveness() {
        let cfg = CFG {
            blocks: vec![
                BasicBlock {
                    id: "B0".to_string(),
                    statements: vec!["let x = 5".to_string()],
                    predecessors: vec![],
                    successors: vec!["B1".to_string()],
                },
                BasicBlock {
                    id: "B1".to_string(),
                    statements: vec!["let y = x + 1".to_string(), "return y".to_string()],
                    predecessors: vec!["B0".to_string()],
                    successors: vec![],
                },
            ],
            entry: "B0".to_string(),
            exit: "B1".to_string(),
        };

        let result = live_variable_analysis(&cfg);

        // En B1, y está viva (se usa en return)
        assert!(result.in_facts.get("B1").unwrap().contains("y"));
        
        // En B0, x está viva (se usa en B1)
        assert!(result.out_facts.get("B0").unwrap().contains("x"));
    }
}
```

***

### 2.3. **Def-Use Chains (Cadenas Definición-Uso)**

**Fórmulas:**

**Def-Use Chain:**
\[
\text{DU}(d) = \{u \mid \exists \text{ path } d \to u \text{ sin redefinición}\}
\]

**Use-Def Chain:**
\[
\text{UD}(u) = \{d \mid \exists \text{ path } d \to u \text{ sin redefinición}\}
\]

**Implementación en Rust:**

```rust
// src/def_use_chains.rs
use std::collections::{HashMap, HashSet};

pub struct DefUseChain {
    pub definitions: HashMap<String, Vec<Definition>>,
    pub uses: HashMap<String, Vec<Use>>,
    pub du_chains: HashMap<String, HashSet<String>>,
    pub ud_chains: HashMap<String, HashSet<String>>,
}

pub struct Definition {
    pub variable: String,
    pub block_id: String,
    pub statement_index: usize,
}

pub struct Use {
    pub variable: String,
    pub block_id: String,
    pub statement_index: usize,
}

pub fn build_def_use_chains(cfg: &CFG) -> DefUseChain {
    let mut definitions: HashMap<String, Vec<Definition>> = HashMap::new();
    let mut uses: HashMap<String, Vec<Use>> = HashMap::new();

    // Extraer definiciones y usos
    for block in &cfg.blocks {
        let mut defined_in_block = HashSet::new();

        for (i, stmt) in block.statements.iter().enumerate() {
            // Extraer definiciones
            if let Some(var_name) = extract_variable_name(stmt) {
                definitions
                    .entry(var_name.clone())
                    .or_insert_with(Vec::new)
                    .push(Definition {
                        variable: var_name.clone(),
                        block_id: block.id.clone(),
                        statement_index: i,
                    });
                defined_in_block.insert(var_name);
            }

            // Extraer usos
            let used_vars = get_used_variables(block);
            for var in used_vars {
                uses.entry(var.clone())
                    .or_insert_with(Vec::new)
                    .push(Use {
                        variable: var.clone(),
                        block_id: block.id.clone(),
                        statement_index: i,
                    });
            }
        }
    }

    // Construir DU chains
    let mut du_chains: HashMap<String, HashSet<String>> = HashMap::new();

    for (var, defs) in &definitions {
        for def in defs {
            // Para cada definición, encontrar todos los usos alcanzables
            let reachable_uses = find_reachable_uses(cfg, def, &uses);
            du_chains.insert(
                format!("{}:{}:{}", def.block_id, def.statement_index, var),
                reachable_uses,
            );
        }
    }

    // Construir UD chains (inverso)
    let mut ud_chains: HashMap<String, HashSet<String>> = HashMap::new();

    for (var, uses) in &uses {
        for use_ in uses {
            let reaching_defs = find_reaching_definitions(cfg, use_, &definitions);
            ud_chains.insert(
                format!("{}:{}:{}", use_.block_id, use_.statement_index, var),
                reaching_defs,
            );
        }
    }

    DefUseChain {
        definitions,
        uses,
        du_chains,
        ud_chains,
    }
}

fn find_reachable_uses(
    cfg: &CFG,
    def: &Definition,
    uses: &HashMap<String, Vec<Use>>,
) -> HashSet<String> {
    let mut reachable = HashSet::new();
    let mut visited = HashSet::new();
    let mut queue = vec![def.block_id.clone()];

    while let Some(block_id) = queue.pop() {
        if visited.contains(&block_id) {
            continue;
        }
        visited.insert(block_id.clone());

        let block = cfg.blocks.iter().find(|b| b.id == block_id).unwrap();

        // Buscar usos en este bloque
        if let Some(var_uses) = uses.get(&def.variable) {
            for use_ in var_uses {
                if use_.block_id == block_id && use_.statement_index > def.statement_index {
                    reachable.insert(format!("{}:{}", use_.block_id, use_.statement_index));
                }
            }
        }

        // Añadir sucesores
        for succ in &block.successors {
            if !visited.contains(succ) {
                queue.push(succ.clone());
            }
        }
    }

    reachable
}

fn find_reaching_definitions(
    cfg: &CFG,
    use_: &Use,
    definitions: &HashMap<String, Vec<Definition>>,
) -> HashSet<String> {
    let mut reaching = HashSet::new();

    // Análisis hacia atrás desde el uso
    if let Some(var_defs) = definitions.get(&use_.variable) {
        for def in var_defs {
            if can_reach(cfg, &def.block_id, &use_.block_id) {
                reaching.insert(format!("{}:{}", def.block_id, def.statement_index));
            }
        }
    }

    reaching
}

fn can_reach(cfg: &CFG, from: &str, to: &str) -> bool {
    // Verificar si hay path desde 'from' hasta 'to'
    let mut visited = HashSet::new();
    let mut queue = vec![from.to_string()];

    while let Some(current) = queue.pop() {
        if current == to {
            return true;
        }

        if visited.contains(&current) {
            continue;
        }
        visited.insert(current.clone());

        let block = cfg.blocks.iter().find(|b| b.id == current).unwrap();
        for succ in &block.successors {
            queue.push(succ.clone());
        }
    }

    false
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_def_use_chain() {
        let cfg = CFG {
            blocks: vec![
                BasicBlock {
                    id: "B0".to_string(),
                    statements: vec!["let x = 5".to_string()],
                    predecessors: vec![],
                    successors: vec!["B1".to_string()],
                },
                BasicBlock {
                    id: "B1".to_string(),
                    statements: vec!["let y = x + 1".to_string(), "return y".to_string()],
                    predecessors: vec!["B0".to_string()],
                    successors: vec![],
                },
            ],
            entry: "B0".to_string(),
            exit: "B1".to_string(),
        };

        let du_chain = build_def_use_chains(&cfg);

        // x definida en B0:0 debe alcanzar uso en B1:0
        assert!(du_chain.du_chains.contains_key("B0:0:x"));
    }
}
```

***

## 3. Detección de Clones (Clone Detection)

### 3.1. **Similaridad de Jaccard**

**Fórmula:**
\[
\text{Jaccard}(A, B) = \frac{|T_A \cap T_B|}{|T_A \cup T_B|}
\]

### 3.2. **Similaridad de Coseno**

**Fórmula:**
\[
\text{Cosine}(A, B) = \frac{\sum_{t \in T} \text{tf}(t, A) \cdot \text{tf}(t, B)}{\sqrt{\sum_{t \in T} \text{tf}(t, A)^2} \cdot \sqrt{\sum_{t \in T} \text{tf}(t, B)^2}}
\]

### 3.3. **Hashing de k-grams (Rabin-Karp)**

**Fórmula:**
\[
H(s_i, k) = \left( \sum_{j=0}^{k-1} s_{i+j} \cdot b^{k-1-j} \right) \mod m
\]

**Hash rolling:**
\[
H(s_{i+1}, k) = \left( (H(s_i, k) - s_i \cdot b^{k-1}) \cdot b + s_{i+k} \right) \mod m
\]

**Implementación en Rust:**

```rust
// src/clone_detection.rs
use tree_sitter::{Tree, Node};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

pub struct ClonePair {
    pub file_a: String,
    pub file_b: String,
    pub similarity: f64,
    pub clone_type: CloneType,
}

pub enum CloneType {
    Type1, // Exacto (mismos tokens)
    Type2, // Renombrado (mismos tokens, identificadores distintos)
    Type3, // Modificado (statements añadidos/eliminados)
    Type4, // Semántico (lógica equivalente, sintaxis distinta)
}

pub struct CloneDetector {
    k: usize,
    threshold: f64,
}

impl CloneDetector {
    pub fn new(k: usize, threshold: f64) -> Self {
        Self { k, threshold }
    }

    pub fn detect_clones(
        &self,
        trees: &HashMap<String, Tree>,
        language: &str,
    ) -> Vec<ClonePair> {
        let mut clones = Vec::new();
        let file_names: Vec<&String> = trees.keys().collect();

        // Extraer k-grams de cada archivo
        let kgrams: HashMap<&String, HashSet<String>> = trees
            .iter()
            .map(|(name, tree)| (name, self.extract_kgrams(tree, language)))
            .collect();

        // Comparar todos los pares
        for i in 0..file_names.len() {
            for j in (i + 1)..file_names.len() {
                let file_a = file_names[i];
                let file_b = file_names[j];

                let kgrams_a = kgrams.get(file_a).unwrap();
                let kgrams_b = kgrams.get(file_b).unwrap();

                let similarity = self.jaccard_similarity(kgrams_a, kgrams_b);

                if similarity >= self.threshold {
                    clones.push(ClonePair {
                        file_a: file_a.clone(),
                        file_b: file_b.clone(),
                        similarity,
                        clone_type: self.classify_clone_type(kgrams_a, kgrams_b, similarity),
                    });
                }
            }
        }

        clones
    }

    fn extract_kgrams(&self, tree: &Tree, language: &str) -> HashSet<String> {
        let tokens = self.tokenize_ast(tree.root_node(), language);
        let mut kgrams = HashSet::new();

        if tokens.len() >= self.k {
            for i in 0..=(tokens.len() - self.k) {
                let gram = tokens[i..i + self.k].join(" ");
                kgrams.insert(gram);
            }
        }

        kgrams
    }

    fn tokenize_ast(&self, node: Node, language: &str) -> Vec<String> {
        let mut tokens = Vec::new();

        // Tokenizar nodos terminales
        if node.child_count() == 0 {
            let text = node.text().trim();
            if !text.is_empty() && !is_whitespace_only(text) {
                tokens.push(text.to_string());
            }
        } else {
            // Recorrer hijos
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    tokens.extend(self.tokenize_ast(child, language));
                }
            }
        }

        tokens
    }

    fn jaccard_similarity(&self, set_a: &HashSet<String>, set_b: &HashSet<String>) -> f64 {
        let intersection = set_a.intersection(set_b).count();
        let union = set_a.union(set_b).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    fn cosine_similarity(&self, set_a: &HashSet<String>, set_b: &HashSet<String>) -> f64 {
        // Calcular frecuencias de términos
        let mut tf_a: HashMap<&String, u32> = HashMap::new();
        let mut tf_b: HashMap<&String, u32> = HashMap::new();

        for token in set_a {
            *tf_a.entry(token).or_insert(0) += 1;
        }

        for token in set_b {
            *tf_b.entry(token).or_insert(0) += 1;
        }

        // Calcular producto punto
        let mut dot_product = 0.0;
        let mut sum_a = 0.0;
        let mut sum_b = 0.0;

        for token in set_a.union(set_b) {
            let a = *tf_a.get(token).unwrap_or(&0) as f64;
            let b = *tf_b.get(token).unwrap_or(&0) as f64;

            dot_product += a * b;
            sum_a += a * a;
            sum_b += b * b;
        }

        if sum_a == 0.0 || sum_b == 0.0 {
            0.0
        } else {
            dot_product / (sum_a.sqrt() * sum_b.sqrt())
        }
    }

    fn classify_clone_type(
        &self,
        kgrams_a: &HashSet<String>,
        kgrams_b: &HashSet<String>,
        similarity: f64,
    ) -> CloneType {
        if similarity == 1.0 {
            CloneType::Type1 // Exacto
        } else if similarity >= 0.95 {
            CloneType::Type2 // Renombrado
        } else if similarity >= 0.8 {
            CloneType::Type3 // Modificado
        } else {
            CloneType::Type4 // Semántico
        }
    }
}

fn is_whitespace_only(text: &str) -> bool {
    text.chars().all(|c| c.is_whitespace())
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_clone_detection() {
        let source_a = r#"
            fn sum(a: i32, b: i32) -> i32 {
                a + b
            }
        "#;

        let source_b = r#"
            fn multiply(x: i32, y: i32) -> i32 {
                x * y
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree_a = analyzer.parse(source_a);
        let tree_b = analyzer.parse(source_b);

        let mut trees = HashMap::new();
        trees.insert("file_a.rs".to_string(), tree_a);
        trees.insert("file_b.rs".to_string(), tree_b);

        let detector = CloneDetector::new(5, 0.7);
        let clones = detector.detect_clones(&trees, "rust");

        println!("Clones encontrados: {}", clones.len());
        for clone in &clones {
            println!(
                "{} <-> {}: {:.2} (Type {:?})",
                clone.file_a, clone.file_b, clone.similarity, clone.clone_type
            );
        }
    }
}
```

***

## 4. Code Property Graph (CPG)

### 4.1. **Composición de Grafos**

**Fórmula:**
\[
\text{CPG} = \text{AST} \cup \text{CFG} \cup \text{DUC} \cup \text{CG}
\]

**Implementación en Rust:**

```rust
// src/code_property_graph.rs
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use std::collections::HashMap;

pub struct CPG {
    pub graph: DiGraph<CPGNode, CPGEdge>,
    pub ast_nodes: HashMap<String, NodeIndex>,
    pub cfg_nodes: HashMap<String, NodeIndex>,
    pub duc_edges: HashMap<String, Vec<(NodeIndex, NodeIndex)>>,
    pub cg_edges: HashMap<String, Vec<(NodeIndex, NodeIndex)>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CPGNode {
    AST(ASTNode),
    CFG(CFGNode),
    DUC(DUCNode),
    CG(CGNode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ASTNode {
    pub kind: String,
    pub text: String,
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CFGNode {
    pub block_id: String,
    pub statements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DUCNode {
    pub variable: String,
    pub definition_point: String,
    pub use_point: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CGNode {
    pub caller: String,
    pub callee: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CPGEdge {
    ASTEdge(ASTEdgeType),
    CFGEdge(CFGEdgeType),
    DUCEdge,
    CGEdge,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ASTEdgeType {
    Parent,
    Child,
    Sibling,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CFGEdgeType {
    ControlFlow,
    ConditionTrue,
    ConditionFalse,
}

impl CPG {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            ast_nodes: HashMap::new(),
            cfg_nodes: HashMap::new(),
            duc_edges: HashMap::new(),
            cg_edges: HashMap::new(),
        }
    }

    pub fn build(&mut self, tree: &Tree, cfg: &CFG, du_chain: &DefUseChain, call_graph: &CallGraph) {
        // 1. Construir AST
        self.build_ast(tree.root_node(), None);

        // 2. Construir CFG
        self.build_cfg(cfg);

        // 3. Construir DUC
        self.build_duc(du_chain);

        // 4. Construir CG
        self.build_cg(call_graph);
    }

    fn build_ast(&mut self, node: Node, parent_idx: Option<NodeIndex>) {
        let ast_node = ASTNode {
            kind: node.kind().to_string(),
            text: node.text().trim().to_string(),
            start_line: node.start_position().row as u32,
            start_column: node.start_position().column as u32,
            end_line: node.end_position().row as u32,
            end_column: node.end_position().column as u32,
        };

        let node_idx = self.graph.add_node(CPGNode::AST(ast_node));
        let key = format!("{}:{}:{}", node.kind(), ast_node.start_line, ast_node.start_column);
        self.ast_nodes.insert(key, node_idx);

        // Arista desde padre
        if let Some(parent) = parent_idx {
            self.graph.add_edge(parent, node_idx, CPGEdge::ASTEdge(ASTEdgeType::Parent));
        }

        // Recorrer hijos
        let mut prev_sibling_idx = None;
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let child_idx = self.build_ast(child, Some(node_idx));

                // Arista entre hermanos
                if let Some(prev_sibling) = prev_sibling_idx {
                    self.graph.add_edge(prev_sibling, child_idx, CPGEdge::ASTEdge(ASTEdgeType::Sibling));
                }

                prev_sibling_idx = Some(child_idx);
            }
        }

        node_idx
    }

    fn build_cfg(&mut self, cfg: &CFG) {
        for block in &cfg.blocks {
            let cfg_node = CFGNode {
                block_id: block.id.clone(),
                statements: block.statements.clone(),
            };

            let node_idx = self.graph.add_node(CPGNode::CFG(cfg_node));
            self.cfg_nodes.insert(block.id.clone(), node_idx);
        }

        // Aristas de control de flujo
        for block in &cfg.blocks {
            let from_idx = self.cfg_nodes.get(&block.id).unwrap();

            for succ_id in &block.successors {
                let to_idx = self.cfg_nodes.get(succ_id).unwrap();
                self.graph.add_edge(*from_idx, *to_idx, CPGEdge::CFGEdge(CFGEdgeType::ControlFlow));
            }
        }
    }

    fn build_duc(&mut self, du_chain: &DefUseChain) {
        // Implementación simplificada
        for (def_key, uses) in &du_chain.du_chains {
            for use_key in uses {
                // Crear nodos y aristas DUC
                // (implementación detallada omitida por brevedad)
            }
        }
    }

    fn build_cg(&mut self, call_graph: &CallGraph) {
        for (caller, callees) in &call_graph.graph {
            for callee in callees {
                let cg_node = CGNode {
                    caller: caller.clone(),
                    callee: callee.clone(),
                };

                let node_idx = self.graph.add_node(CPGNode::CG(cg_node));
                self.cg_edges.entry(caller.clone()).or_insert_with(Vec::new).push((node_idx, node_idx));
            }
        }
    }

    pub fn query(&self, query: CPGQuery) -> Vec<NodeIndex> {
        // Implementar queries sobre el CPG
        // Ej: encontrar todas las llamadas a una función
        // Ej: encontrar todos los usos de una variable
        vec![]
    }
}

pub struct CPGQuery {
    pub node_type: Option<String>,
    pub edge_type: Option<String>,
    pub filters: HashMap<String, String>,
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_cpg_construction() {
        let source = r#"
            fn main() {
                helper();
            }

            fn helper() {
                println!("hello");
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);

        let mut cpg = CPG::new();
        // Construir CPG completo (requiere CFG, DUC, CG)
        // cpg.build(&tree, &cfg, &du_chain, &call_graph);

        println!("CPG construido con {} nodos", cpg.graph.node_count());
    }
}
```

***

## 5. Métricas de Deuda Técnica

### 5.1. **Índice de Mantenibilidad (Microsoft)**

**Fórmula:**
\[
\text{MI} = 171 - 5.2 \ln(V) - 0.23 \cdot M - 16.2 \ln(\text{LOC})
\]

**Normalización:**
\[
\text{MI}_{\text{norm}} = \max\left(0, \min\left(100, \frac{\text{MI} \cdot 100}{171}\right)\right)
\]

**Implementación en Rust:**

```rust
// src/maintainability_index.rs
use crate::halstead_metrics::HalsteadMetrics;
use crate::cyclomatic_complexity::CyclomaticComplexity;

pub struct MaintainabilityIndex {
    pub mi: f64,
    pub mi_normalized: f64,
    pub rating: String,
}

pub fn calculate_maintainability_index(
    halstead: &HalsteadMetrics,
    cyclomatic: &CyclomaticComplexity,
    loc: u32,
) -> MaintainabilityIndex {
    // Fórmula de Microsoft
    let v = halstead.V;
    let m = cyclomatic.complexity as f64;
    let loc_f64 = loc as f64;

    // Evitar log(0)
    let v_safe = if v > 0.0 { v } else { 1.0 };
    let loc_safe = if loc_f64 > 0.0 { loc_f64 } else { 1.0 };

    let mi = 171.0
        - 5.2 * v_safe.ln()
        - 0.23 * m
        - 16.2 * loc_safe.ln();

    // Normalizar a 0-100
    let mi_normalized = (mi * 100.0 / 171.0).clamp(0.0, 100.0);

    // Rating
    let rating = match mi_normalized {
        x if x >= 80.0 => "Muy fácil de mantener".to_string(),
        x if x >= 60.0 => "Fácil de mantener".to_string(),
        x if x >= 40.0 => "Moderado".to_string(),
        x if x >= 20.0 => "Difícil de mantener".to_string(),
        _ => "Muy difícil de mantener".to_string(),
    };

    MaintainabilityIndex {
        mi,
        mi_normalized,
        rating,
    }
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use crate::halstead_metrics::calculate_halstead;
    use crate::cyclomatic_complexity::calculate_cyclomatic_complexity;
    use tree_sitter_rust;

    #[test]
    fn test_maintainability() {
        let source = r#"
            fn complex_function(x: i32, y: i32, z: i32) -> i32 {
                if x > 0 && y > 0 {
                    for i in 0..x {
                        if i % 2 == 0 {
                            println!("even: {}", i);
                        }
                    }
                } else if x < 0 {
                    println!("negative");
                }
                x + y + z
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);

        let halstead = calculate_halstead(&tree, "rust");
        let cyclomatic = calculate_cyclomatic_complexity(&tree);
        let loc = source.lines().count() as u32;

        let mi = calculate_maintainability_index(&halstead, &cyclomatic, loc);

        println!("Índice de Mantenibilidad: {:.2}", mi.mi);
        println!("Normalizado: {:.2}", mi.mi_normalized);
        println!("Rating: {}", mi.rating);
    }
}
```

***

## 6. Análisis de Dependencias (Detección de Ciclos)

### 6.1. **Algoritmo de Tarjan para SCC**

**Implementación en Rust:**

```rust
// src/dependency_analysis.rs
use std::collections::{HashMap, HashSet, VecDeque};

pub struct DependencyGraph {
    pub graph: HashMap<String, Vec<String>>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            graph: HashMap::new(),
        }
    }

    pub fn add_dependency(&mut self, from: String, to: String) {
        self.graph.entry(from).or_insert_with(Vec::new).push(to);
    }

    pub fn find_cycles(&self) -> Vec<Vec<String>> {
        tarjan_scc(&self.graph)
    }
}

pub fn tarjan_scc(graph: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut index_counter = 0;
    let mut stack: VecDeque<String> = VecDeque::new();
    let mut lowlinks: HashMap<String, usize> = HashMap::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut on_stack: HashSet<String> = HashSet::new();
    let mut sccs: Vec<Vec<String>> = Vec::new();

    fn strongconnect(
        v: &str,
        graph: &HashMap<String, Vec<String>>,
        index_counter: &mut usize,
        stack: &mut VecDeque<String>,
        lowlinks: &mut HashMap<String, usize>,
        index: &mut HashMap<String, usize>,
        on_stack: &mut HashSet<String>,
        sccs: &mut Vec<Vec<String>>,
    ) {
        index.insert(v.to_string(), *index_counter);
        lowlinks.insert(v.to_string(), *index_counter);
        *index_counter += 1;
        stack.push_back(v.to_string());
        on_stack.insert(v.to_string());

        if let Some(successors) = graph.get(v) {
            for w in successors {
                if !index.contains_key(w) {
                    // Sucesor no visitado
                    strongconnect(
                        w,
                        graph,
                        index_counter,
                        stack,
                        lowlinks,
                        index,
                        on_stack,
                        sccs,
                    );
                    let lowlink_w = *lowlinks.get(w).unwrap();
                    let lowlink_v = lowlinks.get_mut(v).unwrap();
                    *lowlink_v = (*lowlink_v).min(lowlink_w);
                } else if on_stack.contains(w) {
                    // Sucesor en stack (parte del mismo SCC)
                    let index_w = *index.get(w).unwrap();
                    let lowlink_v = lowlinks.get_mut(v).unwrap();
                    *lowlink_v = (*lowlink_v).min(index_w);
                }
            }
        }

        // Si v es raíz de un SCC
        if lowlinks.get(v) == index.get(v) {
            let mut scc = Vec::new();
            loop {
                let w = stack.pop_back().unwrap();
                on_stack.remove(&w);
                scc.push(w.clone());
                if w == v {
                    break;
                }
            }
            sccs.push(scc);
        }
    }

    // Ejecutar para cada nodo no visitado
    for v in graph.keys() {
        if !index.contains_key(v) {
            strongconnect(
                v,
                graph,
                &mut index_counter,
                &mut stack,
                &mut lowlinks,
                &mut index,
                &mut on_stack,
                &mut sccs,
            );
        }
    }

    sccs
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle_detection() {
        let mut graph = DependencyGraph::new();
        graph.add_dependency("A".to_string(), "B".to_string());
        graph.add_dependency("B".to_string(), "C".to_string());
        graph.add_dependency("C".to_string(), "A".to_string()); // Ciclo
        graph.add_dependency("D".to_string(), "B".to_string());

        let cycles = graph.find_cycles();

        println!("Ciclos encontrados: {}", cycles.len());
        for cycle in &cycles {
            println!("Ciclo: {:?}", cycle);
        }

        // Debería encontrar el ciclo A -> B -> C -> A
        assert!(cycles.iter().any(|cycle| {
            cycle.contains(&"A".to_string()) &&
            cycle.contains(&"B".to_string()) &&
            cycle.contains(&"C".to_string())
        }));
    }
}
```

***

## 7. Tree-sitter Avanzado

### 7.1. **Queries con S-expressions**

**Ejemplo de query:**

```rust
// src/tree_sitter_queries.rs
use tree_sitter::{Tree, Query, QueryCursor, Node};

pub fn extract_function_definitions(tree: &Tree, language: &str) -> Vec<FunctionInfo> {
    let query_source = match language {
        "rust" => r#"
            (function_item
                name: (identifier) @function.name
                parameters: (parameters) @function.params
                return_type: (type_identifier)? @function.return_type
            )
        "#,
        "typescript" => r#"
            (function_declaration
                name: (identifier) @function.name
                parameters: (formal_parameters) @function.params
                return_type: (type_annotation)? @function.return_type
            )
        "#,
        _ => return vec![],
    };

    let query = Query::new(tree.language(), query_source).unwrap();
    let mut cursor = QueryCursor::new();
    let matches = cursor.matches(&query, tree.root_node(), tree.root_node().text().as_bytes());

    let mut functions = Vec::new();

    for m in matches {
        let mut name = None;
        let mut params = None;
        let mut return_type = None;

        for capture in m.captures {
            let node = capture.node;
            match capture.index {
                0 => name = Some(node.text()),
                1 => params = Some(node.text()),
                2 => return_type = Some(node.text()),
                _ => {}
            }
        }

        functions.push(FunctionInfo {
            name: name.unwrap_or_default(),
            params: params.unwrap_or_default(),
            return_type,
        });
    }

    functions
}

pub struct FunctionInfo {
    pub name: String,
    pub params: String,
    pub return_type: Option<String>,
}

// Ejemplo de uso
#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter_rust;

    #[test]
    fn test_extract_functions() {
        let source = r#"
            fn add(a: i32, b: i32) -> i32 {
                a + b
            }

            fn greet(name: &str) {
                println!("Hello, {}", name);
            }
        "#;

        let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
        let tree = analyzer.parse(source);

        let functions = extract_function_definitions(&tree, "rust");

        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "add");
        assert_eq!(functions [wippy](https://wippy.ai/es/lua/text/treesitter).name, "greet");
    }
}
```

***

## 8. Ejemplo Integrado: Análisis Completo

```rust
// src/main.rs
use tree_sitter_rust;
use std::fs;

mod parser;
mod cyclomatic_complexity;
mod halstead_metrics;
mod coupling_metrics;
mod nesting_depth;
mod dataflow_analysis;
mod clone_detection;
mod maintainability_index;
mod dependency_analysis;
mod tree_sitter_queries;

use parser::CodeAnalyzer;
use cyclomatic_complexity::calculate_cyclomatic_complexity;
use halstead_metrics::calculate_halstead;
use coupling_metrics::{CallGraph, calculate_coupling_metrics};
use nesting_depth::calculate_nesting_depth;
use maintainability_index::calculate_maintainability_index;
use dependency_analysis::DependencyGraph;

pub struct CodeAnalysisReport {
    pub file: String,
    pub cyclomatic_complexity: u32,
    pub halstead_volume: f64,
    pub halstead_effort: f64,
    pub maintainability_index: f64,
    pub max_nesting: u32,
    pub total_functions: usize,
    pub dependencies: Vec<String>,
}

fn analyze_file(path: &str) -> CodeAnalysisReport {
    let source = fs::read_to_string(path).expect("Cannot read file");
    
    let mut analyzer = CodeAnalyzer::new(tree_sitter_rust::LANGUAGE.into());
    let tree = analyzer.parse(&source);

    // Métricas
    let cyclomatic = calculate_cyclomatic_complexity(&tree);
    let halstead = calculate_halstead(&tree, "rust");
    let nesting = calculate_nesting_depth(&tree, "rust");
    let mi = calculate_maintainability_index(&halstead, &cyclomatic, source.lines().count() as u32);

    // Grafo de llamadas
    let mut call_graph = CallGraph::new();
    call_graph.build(&tree, "rust");
    let coupling = calculate_coupling_metrics(&call_graph);

    CodeAnalysisReport {
        file: path.to_string(),
        cyclomatic_complexity: cyclomatic.complexity,
        halstead_volume: halstead.V,
        halstead_effort: halstead.E,
        maintainability_index: mi.mi_normalized,
        max_nesting: nesting.max_depth,
        total_functions: call_graph.graph.len(),
        dependencies: vec![], // Extraer de imports
    }
}

fn main() {
    let report = analyze_file("src/main.rs");

    println!("=== Reporte de Análisis de Código ===");
    println!("Archivo: {}", report.file);
    println!("Complejidad Ciclomática: {}", report.cyclomatic_complexity);
    println!("Volumen Halstead: {:.2}", report.halstead_volume);
    println!("Esfuerzo Halstead: {:.2}", report.halstead_effort);
    println!("Índice de Mantenibilidad: {:.2}", report.maintainability_index);
    println!("Profundidad Máxima de Anidamiento: {}", report.max_nesting);
    println!("Total Funciones: {}", report.total_functions);
}
```
