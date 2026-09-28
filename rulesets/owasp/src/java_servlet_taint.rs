//! Servlet-aware intra-file taint analysis for Java, shared by the
//! Java OWASP rules (XSS, path traversal, command/SQL/LDAP/XPath
//! injection, …).
//!
//! The neutral AST's Java mapping has two shapes rules must know about
//! (see `parsers/treesitter-java`):
//!
//! * `method_invocation` / `object_creation_expression` → [`NodeKind::Call`],
//!   children `[object?, name, arguments]` — so `call.first_child()` is the
//!   *receiver*, not the callee. [`split_call`] normalizes this.
//! * `local_variable_declaration` → [`NodeKind::Assignment`] whose children
//!   are `[type, variable_declarator…]` — the declarator (not the first
//!   child) holds `[name, value]`.
//!
//! The analysis is a single document-order pass. Assignments/declarations
//! set a variable's taint state, and call side effects (`list.add(x)`,
//! `sb.append(x)`, `pb.command(x)`, `cookie.setSecure(true)`) mutate
//! container/builder state as they are encountered. Two properties make
//! the pass survive real servlet code:
//!
//! * **Weak updates inside branches.** An assignment in an `if`/`for`/`try`
//!   body only *joins* the state of both paths instead of overwriting it.
//!   The benchmark's ubiquitous `if (param == null) param = "";` null-guard
//!   is not a sanitizer, and treating it as a strong update laundered real
//!   request data in ~800 files.
//! * **A state snapshot per program point.** The pass records the state
//!   that holds at every offset, so a rule asking about a sink expression
//!   is answered with the state at *that expression's position* rather than
//!   one flat end-of-file state. That keeps a helper method's variables
//!   (`bar`, `param` in the OWASP inner-class family) from clobbering the
//!   servlet method's taint, and a method's writes are dropped when it
//!   ends.
//!
//! Expressions are evaluated against the state at their own position:
//!
//! * string/number literals and `new`-constructed objects are clean,
//! * identifiers read their current state,
//! * `ArrayList`-style containers remember the taint of each `add`ed
//!   element as positional *slots*, so `remove(0); get(0)` and
//!   `get(1)` resolve to different elements,
//! * conditional expressions (`cond ? a : b`) resolve to one branch when
//!   `cond` is a constant-foldable integer/boolean expression (the
//!   benchmark's "always-true ternary" safe pattern),
//! * everything else is conservative: an expression is tainted when any
//!   sub-expression is,
//! * calls to HTML/URL/SQL encoders (`encodeForHTML`, `Encode.forHtml`, …)
//!   cleanse their result regardless of their arguments.
//!
//! This is deliberately a *value-flow* analysis, not a whole-program one:
//! a helper method propagates the taint of its arguments, so
//! `thing.doSomething(param)` is tainted when `param` is, and clean when it
//! is called with the benchmark's `"barbarians_at_the_gate"` constant.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use vord_ast::{AstNode, NodeKind};

/// Call-expression shape normalized out of the Java neutral-AST mapping.
pub struct CallParts<'a> {
    /// Receiver expression (`object`), if any.
    pub receiver: Option<&'a AstNode>,
    /// Source text of the receiver, empty when absent.
    pub receiver_text: String,
    /// Method name — or, for `new Foo(…)`, the constructed type.
    pub method: String,
    /// Constructed type for `new Foo(…)`, empty for method calls.
    pub type_text: String,
    /// Whether the call is an object creation (`new …`).
    pub is_new: bool,
    /// Argument expressions.
    pub args: Vec<&'a AstNode>,
}

const ARG_LIST_KIND: &str = "argument_list";
const DECLARATOR_KIND: &str = "variable_declarator";
/// `ternary_expression` is the tree-sitter-java kind; some grammars call
/// it `conditional_expression`.
const COND_KINDS: &[&str] = &["ternary_expression", "conditional_expression"];
const ENHANCED_FOR_KIND: &str = "enhanced_for_statement";
const IF_KIND: &str = "if_statement";
const SWITCH_KIND: &str = "switch_expression";
const SWITCH_BLOCK_KIND: &str = "switch_block";
const SWITCH_LABEL_KIND: &str = "switch_label";
const PAREN_KIND: &str = "parenthesized_expression";
const BREAK_KIND: &str = "break_statement";
const PARAMS_KIND: &str = "formal_parameters";
const PARAM_KIND: &str = "formal_parameter";
const RETURN_KIND: &str = "return_statement";

/// A method declared in the same file: its parameter names and body, so a
/// call to it can be answered by analyzing that body.
struct MethodDef {
    params: Vec<String>,
    body: AstNode,
}

/// What a call to a same-file helper evaluates to: whether its return
/// value is tainted, and whether it is request data that was only
/// *encoded*. Carrying both across the call boundary is what keeps
/// `bar = new Test().doSomething(param)` — where the helper runs the
/// encoder — classified as encoded-but-unvalidated instead of collapsing
/// to a plain bool.
struct MethodOutcome {
    tainted: bool,
    encoded: bool,
}

/// Shared handle to the file's method index. Every [`Flow`] snapshot points
/// at the same one, so cloning a snapshot stays cheap.
type Methods = Arc<HashMap<String, MethodDef>>;

/// Same-file methods that have already been expanded, so a helper that
/// calls itself — directly or around a cycle — terminates instead of
/// recursing forever. Held behind an [`Arc`] because every [`Flow`] needs
/// its own copy of the set.
type Inlining = Arc<HashSet<String>>;

/// Indexes every method in the file by name. Overloaded names are dropped
/// rather than guessed at — an ambiguous signature is not worth inlining.
fn index_methods(ast: &AstNode) -> HashMap<String, MethodDef> {
    let mut found: Vec<(String, MethodDef)> = Vec::new();
    for node in ast.descendants() {
        if *node.kind() != NodeKind::FunctionDef {
            continue;
        }
        let children = node.children();
        let Some(params) = children.iter().find(|c| is_other(c, PARAMS_KIND)) else {
            continue;
        };
        // `method_declaration` is `[type, name, params, body]`, so the
        // method name is the child just before the parameter list.
        let Some(index) = children.iter().position(|c| is_other(c, PARAMS_KIND)) else {
            continue;
        };
        let Some(name) = index.checked_sub(1).and_then(|i| children.get(i)) else {
            continue;
        };
        if *name.kind() != NodeKind::Identifier {
            continue;
        }
        let Some(body) = children.last().filter(|c| is_other(c, "block")) else {
            continue;
        };
        let params = params
            .children()
            .iter()
            .filter(|p| is_other(p, PARAM_KIND))
            .filter_map(|p| p.children().iter().rev().find(|c| *c.kind() == NodeKind::Identifier))
            .map(|c| c.text().to_string())
            .collect();
        found.push((
            name.text().to_string(),
            MethodDef { params, body: body.clone() },
        ));
    }
    let mut methods = HashMap::new();
    for (name, def) in found {
        if methods.insert(name.clone(), def).is_some() {
            // A second definition of the same name: drop the entry so the
            // call falls back to plain argument propagation.
            methods.remove(&name);
        }
    }
    methods
}

/// Constructs whose bodies may or may not execute: an assignment inside one
/// of these joins the incoming state instead of replacing it.
const BRANCH_KINDS: &[&str] = &[
    IF_KIND,
    "ternary_expression",
    "conditional_expression",
    "switch_expression",
    "switch_block",
    "switch_block_statement_group",
    "switch_rule",
    "for_statement",
    ENHANCED_FOR_KIND,
    "while_statement",
    "do_statement",
    "loop_statement",
    "catch_clause",
];

/// Whether a node's children sit on a path that may not execute.
fn is_branch(node: &AstNode) -> bool {
    match node.kind() {
        NodeKind::Other(kind) => BRANCH_KINDS.contains(&&**kind),
        _ => false,
    }
}

fn is_other(node: &AstNode, kind: &str) -> bool {
    *node.kind() == NodeKind::Other(vord_ast::intern(kind))
}

/// Splits a Java [`NodeKind::Call`] into receiver / method / arguments.
pub fn split_call(call: &AstNode) -> Option<CallParts<'_>> {
    if *call.kind() != NodeKind::Call {
        return None;
    }
    let children = call.children();
    if children.is_empty() {
        return None;
    }
    let (args, head): (Vec<&AstNode>, &[AstNode]) = if is_other(children.last().unwrap(), ARG_LIST_KIND)
    {
        (children.last().unwrap().children().iter().collect(), &children[..children.len() - 1])
    } else {
        (children[1..].iter().collect(), &children[..1])
    };
    if head.is_empty() {
        return None;
    }
    // `new Foo(…)` is an object creation; `new Foo().bar(…)` is a method
    // call whose *receiver* is the creation. The leading `new ` alone
    // cannot tell them apart — a creation has the type as the only callee
    // before the argument list, while a chained call has a second one.
    let is_new = call.text().trim_start().starts_with("new ") && head.len() == 1;
    if is_new {
        let type_text = head[0].text().to_string();
        Some(CallParts {
            receiver: None,
            receiver_text: String::new(),
            method: String::new(),
            type_text: type_text.split('<').next().unwrap_or("").trim().to_string(),
            is_new: true,
            args,
        })
    } else {
        let (receiver, method) = if head.len() >= 2 {
            (Some(&head[0]), head[head.len() - 1].text().to_string())
        } else {
            (None, head[0].text().to_string())
        };
        Some(CallParts {
            receiver,
            receiver_text: receiver.map(|r| r.text().to_string()).unwrap_or_default(),
            method,
            type_text: String::new(),
            is_new: false,
            args,
        })
    }
}

/// Servlet request methods that introduce user-controlled data.
///
/// `getTheParameter` is the OWASP Benchmark's `SeparateClassRequest` helper,
/// which reaches the request through a different object and is a genuine
/// source (`getTheValue`, its sibling, is not listed — it returns a
/// constant).
const REQUEST_SOURCES: &[&str] = &[
    "getParameter",
    "getTheParameter",
    "getParameterMap",
    "getParameterNames",
    "getParameterValues",
    "getHeader",
    "getHeaders",
    "getQueryString",
    "getCookies",
    "getReader",
    "getInputStream",
    "getPathInfo",
    "getPathTranslated",
    "getRemoteUser",
    "getPart",
    "getParts",
    "getRequestURI",
    // Pulls the next element out of a request-derived `Enumeration`
    // (`getHeaderNames()`, `getParameterNames()`, `getHeaders(…)`): the
    // element is attacker-chosen just as much as the request is.
    "nextElement",
];

/// Encoders trusted to neutralize untrusted data for output contexts.
const SANITIZERS: &[&str] = &[
    "encodeForHTML",
    "encodeForHTMLAttribute",
    "encodeForCSS",
    "encodeForJavaScript",
    "encodeForURL",
    "encodeForXML",
    "encodeForXMLAttribute",
    "encodeForBase64",
    "encodeForSQL",
    "canonicalize",
    "forHtml",
    "forHtmlAttribute",
    "forHtmlContent",
    "forCssString",
    "forCssUrl",
    "forJavaScript",
    "forJavaScriptBlock",
    "forJavaScriptSource",
    "forUriComponent",
    "forXml",
    "forXmlComment",
    "forXmlContent",
    "forXmlAttribute",
    // Spring's `HtmlUtils`, and the Apache Commons `StringEscapeUtils`
    // family, are the other two encoders the benchmark treats as
    // neutralizing for an HTML context.
    "htmlEscape",
    "htmlEscapeHtml4",
    "xmlEscape",
    "escapeHtml",
    "escapeHtml4",
    "escapeXml",
    "escapeEcmaScript",
    "escapeJavaScript",
    "escapeJson",
    "escapeSql",
];

/// Positional taint state of one container/builder variable.
type Slots = Vec<bool>;

/// Taint state of the whole file at one program point.
#[derive(Default, Clone)]
struct Flow {
    tainted: HashSet<String>,
    literals: HashMap<String, String>,
    ints: HashMap<String, i64>,
    slots: HashMap<String, Slots>,
    cmd_tainted: HashSet<String>,
    writer_vars: HashSet<String>,
    cookie_vars: HashMap<String, bool>,
    xpath_vars: HashSet<String>,
    ldap_vars: HashSet<String>,
    chars: HashMap<String, char>,
    /// Variables holding request data that has only been *encoded*, not
    /// validated. HTML-escaping makes a value safe to write into a page, but
    /// it is still attacker-controlled data, so a rule about crossing a
    /// trust boundary (`session.setAttribute`) must still see it. Output
    /// rules consult `tainted` alone and correctly treat these as clean.
    encoded: HashSet<String>,
    /// Keyed containers (`map.put(k, v)` / `map.get(k)`), kept separately
    /// from the positional `slots` because a `HashMap` read is by key, not
    /// by index.
    maps: HashMap<String, HashMap<String, bool>>,
    /// Method bodies declared in the same file, so `eval` can answer a call
    /// to a local helper from that helper's own value flow. Shared, not
    /// cloned, because every state snapshot references the same index.
    methods: Methods,
    /// Same-file methods already expanded on the current path. A call to
    /// one of these is left to ordinary argument propagation, which bounds
    /// inlining and makes a recursive helper terminate.
    inlining: Inlining,
}

/// Intra-file taint states computed by [`ServletTaint::analyze`].
///
/// Rules ask about a *sink expression*, so what they need is the state at
/// that expression's position — not the state at end of file, where a
/// helper method or inner class declared later has already overwritten the
/// very variables the sink reads (the OWASP Benchmark's inner-class family
/// reassigns `bar`/`param` and silently disarms the real sink). The pass
/// therefore records a state snapshot per statement and resolves each query
/// against the last snapshot starting at or before the queried node.
pub struct ServletTaint {
    /// State before the first statement, used by queries that precede every
    /// snapshot.
    initial: Flow,
    /// `(offset the state applies from, state)`, ascending by offset.
    snapshots: Vec<(u32, Flow)>,
}

impl ServletTaint {
    /// Runs the document-order analysis pass over `ast`.
    pub fn analyze(ast: &AstNode) -> Self {
        let methods: Methods = Arc::new(index_methods(ast));
        let inlining: Inlining = Arc::new(HashSet::new());
        let mut pass = Pass::new(methods.clone(), inlining.clone());
        pass.walk(ast, false);
        Self { initial: Flow::new(&methods, &inlining), snapshots: pass.snapshots }
    }

    /// The state that holds at `node`'s position in the file.
    ///
    /// A snapshot is keyed by the offset at which its state *starts to
    /// apply* — the end of the statement that produced it — and looked up
    /// with `<=`, so an expression is answered with the state left behind
    /// by the last statement that finished before it.
    fn flow_at(&self, node: &AstNode) -> &Flow {
        let at = node.byte_range().start as u32;
        self.snapshots
            .iter()
            .rev()
            .find(|(from, _)| *from <= at)
            .map(|(_, flow)| flow)
            .unwrap_or(&self.initial)
    }

    /// Whether `expr` evaluates to user-controlled (tainted) data.
    pub fn is_tainted(&self, expr: &AstNode) -> bool {
        self.flow_at(expr).eval(expr)
    }

    /// The literal string value of `expr`, when statically known.
    pub fn literal_of(&self, expr: &AstNode) -> Option<String> {
        self.flow_at(expr).literal_of(expr)
    }

    /// True for a `response.getWriter()`/`getOutputStream()` chain or a
    /// variable previously assigned one.
    pub fn is_response_writer(&self, expr: &AstNode) -> bool {
        self.flow_at(expr).is_response_writer(expr)
    }

    /// Whether the expression is an XPath engine value (`xpf.newXPath()`,
    /// a variable declared as `javax.xml.xpath.XPath`, …).
    pub fn is_xpath(&self, expr: &AstNode) -> bool {
        self.flow_at(expr).is_xpath(expr)
    }

    /// Whether the expression is a directory/LDAP context value.
    pub fn is_dir_context(&self, expr: &AstNode) -> bool {
        self.flow_at(expr).is_dir_context(expr)
    }

    /// Whether the expression is a servlet `Cookie` object.
    pub fn is_cookie(&self, expr: &AstNode) -> bool {
        self.flow_at(expr).is_cookie(expr)
    }

    /// Whether this cookie has seen `setSecure(true)` before this point.
    pub fn cookie_is_secure(&self, cookie: &AstNode) -> bool {
        self.flow_at(cookie)
            .cookie_vars
            .get(cookie.text())
            .copied()
            .unwrap_or(false)
    }

    /// Whether the expression is a `java.lang.ProcessBuilder` object whose
    /// command has been set from tainted data.
    pub fn is_tainted_command_builder(&self, expr: &AstNode) -> bool {
        self.flow_at(expr).is_tainted_command_builder(expr)
    }

    /// Whether the expression is request-derived data that has been encoded
    /// but never validated. This is the question a trust-boundary rule asks:
    /// storing such a value in the session hands attacker data to code that
    /// will later treat it as trusted, however well it is escaped.
    ///
    /// Covers all three shapes the data arrives in: a variable that
    /// already carries the encoded status, an *inline* encoder call whose
    /// input is itself unvalidated (`session.setAttribute(k,
    /// escapeHtml(param))`), and a same-file helper that returns either.
    pub fn is_unvalidated_request_data(&self, expr: &AstNode) -> bool {
        let flow = self.flow_at(expr);
        flow.eval(expr) || flow.encodedness(expr)
    }
}

/// The document-order walk. Snapshots are pushed in ascending offset order
/// so [`ServletTaint::flow_at`] resolves a position by scanning back.
struct Pass {
    flow: Flow,
    snapshots: Vec<(u32, Flow)>,
}

impl Pass {
    fn new(methods: Methods, inlining: Inlining) -> Self {
        Self { flow: Flow::new(&methods, &inlining), snapshots: Vec::new() }
    }

    fn snapshot(&mut self, from: u32) {
        self.snapshots.push((from, self.flow.clone()));
    }

    /// The index of the case group a `switch` provably selects, when its
    /// selector folds to a char. `None` means "not foldable" and every case
    /// stays reachable.
    fn taken_case(&self, node: &AstNode) -> Option<usize> {
        let selector = node.children().first()?;
        let block = node.children().iter().find(|c| is_other(c, SWITCH_BLOCK_KIND))?;
        let selected = self.flow.eval_char(selector)?;
        block.children().iter().position(|group| {
            group.children().iter().any(|label| {
                is_other(label, SWITCH_LABEL_KIND) && self.label_matches(label, selected)
            })
        })
    }

    /// Walks the selected case group and every group it falls through to,
    /// stopping after the first one that breaks. A group of bare labels
    /// (`case 'C':` with no body) falls into the next group, which is how
    /// the benchmark groups its unsafe arms.
    fn walk_case_groups(&mut self, node: &AstNode, from: usize) {
        let Some(block) = node.children().iter().find(|c| is_other(c, SWITCH_BLOCK_KIND)) else {
            return;
        };
        for group in block.children().iter().skip(from) {
            let breaks = group
                .descendants()
                .any(|n| is_other(n, BREAK_KIND));
            self.walk(group, false);
            if breaks {
                return;
            }
        }
    }

    /// Whether a `case` label covers `selected`. Labels list their
    /// alternatives as consecutive `switch_label` children, so each is
    /// checked on its own.
    fn label_matches(&self, label: &AstNode, selected: char) -> bool {
        label
            .descendants()
            .filter(|n| is_other(n, "character_literal"))
            .filter_map(|n| unquote_char(n.text()))
            .any(|c| c == selected)
    }

    /// For `if (cond) A else B` whose condition folds to a constant, the
    /// index of the arm that always runs — `1` for `then`, `2` for `else`,
    /// `0` when no arm runs at all (a false condition with no `else`).
    /// `None` means "not foldable", and the caller walks both arms as a
    /// join. Returns an index rather than a node so the caller can release
    /// the borrow on `self` before recursing.
    fn taken_branch(&self, node: &AstNode) -> Option<usize> {
        let children = node.children();
        let condition = children.first()?;
        children.get(1)?;
        match self.flow.eval_int_text(condition.text())? {
            0 => Some(if children.len() > 2 { 2 } else { 0 }),
            _ => Some(1),
        }
    }

    /// Walks `node` and its children in document order. `weak` is set
    /// inside a construct whose body may not execute: there an assignment
    /// *joins* the incoming state instead of replacing it, so the
    /// benchmark's `if (param == null) param = "";` null-guard no longer
    /// launders real request data.
    fn walk(&mut self, node: &AstNode, weak: bool) {
        match node.kind() {
            NodeKind::Assignment => {
                self.flow.visit_assignment(node, weak);
                // Keyed at the statement's *end*: the state a later
                // expression sees is the one this statement leaves behind,
                // and a query on the statement's own RHS wants the state
                // that existed while the RHS was evaluated.
                self.snapshot(node.byte_range().end as u32);
                return;
            }
            NodeKind::Call => {
                self.flow.visit_call(node);
                self.snapshot(node.byte_range().end as u32);
                return;
            }
            _ if is_other(node, ENHANCED_FOR_KIND) => {
                // The loop variable is bound for the body, so this snapshot
                // must apply from the end of the iterable expression, not
                // from the end of the whole loop.
                let from = node
                    .children()
                    .get(2)
                    .map(|c| c.byte_range().end as u32)
                    .unwrap_or_else(|| node.byte_range().end as u32);
                self.flow.visit_enhanced_for(node);
                self.snapshot(from);
            }
            _ if is_other(node, SWITCH_KIND) => {
                // `switch (sel) { case 'A': … case 'B': … }` — children
                // `[selector, switch_block]`, the block holding one
                // `switch_block_statement_group` per case. When the
                // selector folds to a char, the matching case is the only
                // one that can run.
                if let Some(index) = self.taken_case(node) {
                    self.walk_case_groups(node, index);
                    return;
                }
            }
            _ if is_other(node, IF_KIND) => {
                // `if (cond) A else B` — children `[cond, A, B?]`. When
                // `cond` folds to a constant the untaken arm is dead code
                // and the taken one always runs, so the arm is walked with
                // *strong* updates and the other is skipped entirely. This
                // is the statement form of the constant ternary the
                // benchmark uses to smuggle a constant into a variable.
                if let Some(index) = self.taken_branch(node) {
                    if let Some(arm) = node.children().get(index) {
                        self.walk(arm, false);
                    }
                    return;
                }
            }
            _ => {}
        }
        let weak = weak || is_branch(node);
        for child in node.children() {
            self.walk(child, weak);
        }
    }
}

/// One program's worth of mutable state, plus the queries rules run against
/// the snapshot that covers their node.
impl Flow {
    fn new(methods: &Methods, inlining: &Inlining) -> Self {
        Self {
            methods: methods.clone(),
            inlining: inlining.clone(),
            ..Self::default()
        }
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// The literal string value of `expr`, when statically known.
    pub fn literal_of(&self, expr: &AstNode) -> Option<String> {
        if let NodeKind::StringLiteral = expr.kind() {
            return Some(unquote(expr.text()));
        }
        if *expr.kind() == NodeKind::Identifier {
            return self.literals.get(expr.text()).cloned();
        }
        None
    }

    /// True for a `response.getWriter()`/`getOutputStream()` chain or a
    /// variable previously assigned one.
    pub fn is_response_writer(&self, expr: &AstNode) -> bool {
        if *expr.kind() == NodeKind::Identifier && self.writer_vars.contains(expr.text()) {
            return true;
        }
        let text = expr.text();
        text.contains("getWriter()") || text.contains("getOutputStream()")
    }

    /// Whether the expression is an XPath engine value (`xpf.newXPath()`,
    /// a variable declared as `javax.xml.xpath.XPath`, …).
    pub fn is_xpath(&self, expr: &AstNode) -> bool {
        if *expr.kind() == NodeKind::Identifier && self.xpath_vars.contains(expr.text()) {
            return true;
        }
        expr.text().contains("XPath") || expr.text().contains("xpath")
    }

    /// Whether the expression is a directory/LDAP context value.
    pub fn is_dir_context(&self, expr: &AstNode) -> bool {
        if *expr.kind() == NodeKind::Identifier && self.ldap_vars.contains(expr.text()) {
            return true;
        }
        expr.text().contains("DirContext")
    }

    /// Whether the expression is a variable that received encoded (but not
    /// validated) request data. The encoding call is a member of
    /// [`SANITIZERS`], so [`Flow::eval`] reports its result clean; this is
    /// the record that request data flowed through it.
    pub fn is_encoded(&self, expr: &AstNode) -> bool {
        *expr.kind() == NodeKind::Identifier && self.encoded.contains(expr.text())
    }

    /// Whether `expr` evaluates to request data that was only *encoded*.
    /// Three shapes qualify:
    ///
    /// * a variable already carrying the status ([`Flow::is_encoded`]),
    /// * an encoder call whose input is itself unvalidated — encoding a
    ///   clean value proves nothing, so `escapeHtml(getTheValue())` over a
    ///   constant does **not** count,
    /// * a same-file helper that returns either of the above, so a helper
    ///   running the encoder does not launder the status for its caller.
    fn encodedness(&self, expr: &AstNode) -> bool {
        if self.is_encoded(expr) {
            return true;
        }
        let Some(call) = split_call(expr) else {
            return false;
        };
        if call.is_new {
            return false;
        }
        if SANITIZERS.contains(&call.method.as_str()) {
            return call.args.iter().any(|a| self.eval(a) || self.encodedness(a));
        }
        self.eval_local_method(&call).is_some_and(|outcome| outcome.encoded)
    }

    /// Whether the expression is a servlet `Cookie` object.
    pub fn is_cookie(&self, expr: &AstNode) -> bool {
        *expr.kind() == NodeKind::Identifier && self.cookie_vars.contains_key(expr.text())
    }

    /// Whether the expression is a `java.lang.ProcessBuilder` object whose
    /// command has been set from tainted data.
    pub fn is_tainted_command_builder(&self, expr: &AstNode) -> bool {
        *expr.kind() == NodeKind::Identifier && self.cmd_tainted.contains(expr.text())
    }

    // ------------------------------------------------------------------
    // Statement side effects
    // ------------------------------------------------------------------

    fn visit_assignment(&mut self, node: &AstNode, weak: bool) {
        let children = node.children();
        if children.is_empty() {
            return;
        }
        // The Java mapping collapses `local_variable_declaration` into
        // `NodeKind::Assignment`; the declarator children are the only
        // structural difference from `x = …` (whose children are
        // `[target, value]`).
        if children.iter().any(|c| is_other(c, DECLARATOR_KIND)) {
            let decl_text = node.text();
            for declarator in children.iter().filter(|c| is_other(c, DECLARATOR_KIND)) {
                let dchildren = declarator.children();
                if dchildren.is_empty() || *dchildren[0].kind() != NodeKind::Identifier {
                    continue;
                }
                let name = dchildren[0].text().to_string();
                let values = &dchildren[1..];
                self.assign(&name, values, decl_text, weak);
            }
        } else {
            let target = &children[0];
            if *target.kind() == NodeKind::Identifier {
                let name = target.text().to_string();
                let text = node.text().to_string();
                self.assign(&name, &children[1..], &text, weak);
            }
        }
    }

    /// Applies an assignment to the state. Under a `weak` update — an
    /// assignment inside a body that may not execute — taint is only ever
    /// *added*: the path where the branch is skipped keeps the old state,
    /// so joining is the only sound result. Killing the variable (and
    /// overwriting its constant/slot state) is left to straight-line code.
    fn assign(&mut self, name: &str, values: &[AstNode], decl_text: &str, weak: bool) {
        let tainted = values.iter().any(|v| self.eval(v));
        if tainted {
            self.tainted.insert(name.to_string());
        } else if !weak {
            self.tainted.remove(name);
        }

        // Encoded-but-unvalidated data. Like taint this only accumulates: a
        // value that has been escaped once stays request-derived for the
        // rest of its scope, whichever branch assigned it. `encodedness`
        // is what makes "escaped" mean "escaped *request* data": it sees
        // through same-file helper calls (the inner-class family) and
        // refuses to mark an escape of a clean input (a constant source
        // is not made unvalidated by escaping it).
        let encoded = values.iter().any(|v| self.encodedness(v));
        if encoded {
            self.encoded.insert(name.to_string());
        } else if !weak {
            self.encoded.remove(name);
        }

        if weak {
            self.assign_roles(name, values, decl_text);
            return;
        }

        // Known string literal value (possibly copied through an identifier).
        let literal = values
            .iter()
            .find_map(|v| self.literal_of(v))
            .or_else(|| {
                values
                    .iter()
                    .find_map(|v| self.eval_int_text(v.text()).map(|i| i.to_string()))
            });
        match literal {
            Some(lit) => {
                self.literals.insert(name.to_string(), lit);
            }
            None => {
                self.literals.remove(name);
            }
        }

        if let Some(v) = values.iter().find_map(|v| self.eval_int_text(v.text())) {
            self.ints.insert(name.to_string(), v);
        } else {
            self.ints.remove(name);
        }

        match values.iter().find_map(|v| self.eval_char(v)) {
            Some(c) => {
                self.chars.insert(name.to_string(), c);
            }
            None => {
                self.chars.remove(name);
            }
        }

        // Container slots: copied when assigned from another container, and
        // seeded from the arguments of a `new Builder(tainted)` so a builder
        // constructed around request data is tainted from the start.
        let slots = values
            .iter()
            .find_map(|v| {
                if *v.kind() == NodeKind::Identifier {
                    self.slots.get(v.text()).cloned()
                } else {
                    None
                }
            })
            .or_else(|| values.iter().find_map(|v| c_args_taint(v, self)))
            .unwrap_or_default();
        self.slots.insert(name.to_string(), slots);

        self.assign_roles(name, values, decl_text);
    }

    /// Type-flavored roles, read off the declaration text — the neutral AST
    /// keeps the Java type node but gives rules no type checker. These are
    /// monotone facts about the variable ("this *is* a response writer"),
    /// so they hold on the branch path as well as the fall-through path.
    fn assign_roles(&mut self, name: &str, values: &[AstNode], decl_text: &str) {
        if decl_text.contains("getWriter()")
            || decl_text.contains("getOutputStream()")
            || decl_text.contains("PrintWriter")
            || decl_text.contains("ServletOutputStream")
        {
            self.writer_vars.insert(name.to_string());
        }
        if decl_text.contains("XPath") {
            self.xpath_vars.insert(name.to_string());
        }
        if decl_text.contains("DirContext") {
            self.ldap_vars.insert(name.to_string());
        }
        if values.iter().any(|v| {
            *v.kind() == NodeKind::Call
                && split_call(v).is_some_and(|c| c.is_new && c.type_text.ends_with("Cookie"))
        }) {
            self.cookie_vars.insert(name.to_string(), false);
        } else if !decl_text.contains("Cookie") {
            self.cookie_vars.remove(name);
        }
    }

    fn visit_enhanced_for(&mut self, node: &AstNode) {
        // `for (Type name : iterable) { … }` — children [type, name, value, body].
        let children = node.children();
        if children.len() >= 3 && *children[1].kind() == NodeKind::Identifier {
            let name = children[1].text().to_string();
            if self.eval(&children[2]) {
                self.tainted.insert(name.clone());
            } else {
                self.tainted.remove(&name);
            }
            self.slots.entry(name).or_default();
        }
    }

    fn visit_call(&mut self, node: &AstNode) {
        let Some(call) = split_call(node) else {
            return;
        };
        let Some(receiver) = call.receiver.filter(|r| *r.kind() == NodeKind::Identifier) else {
            return;
        };
        let var = receiver.text().to_string();
        match call.method.as_str() {
            "add" | "push" => {
                let slot = call.args.first().map(|a| self.eval(a)).unwrap_or(false);
                self.slots.entry(var).or_default().push(slot);
            }
            "put" => {
                // Keyed container write: `map.put("key", value)`.
                let key = call.args.first().and_then(|a| self.literal_of(a));
                if let Some(key) = key {
                    let tainted = call.args.get(1).is_some_and(|a| self.eval(a));
                    self.maps.entry(var).or_default().insert(key, tainted);
                }
            }
            "append" => {
                let slot = call.args.first().map(|a| self.eval(a)).unwrap_or(false);
                self.slots.entry(var).or_default().push(slot);
            }
            "remove" | "removeElement" => {
                if let Some(idx) = call
                    .args
                    .first()
                    .and_then(|a| self.eval_int_text(a.text()))
                    .map(|i| i as usize)
                {
                    if let Some(slots) = self.slots.get_mut(&var) {
                        if idx < slots.len() {
                            slots.remove(idx);
                        }
                    }
                } else {
                    self.slots.remove(&var);
                }
            }
            "command" => {
                let tainted = call.args.iter().any(|a| self.eval(a));
                if tainted {
                    self.cmd_tainted.insert(var);
                } else {
                    self.cmd_tainted.remove(&var);
                }
            }
            "setSecure" => {
                let secure = call
                    .args
                    .first()
                    .map(|a| a.text().trim() == "true")
                    .unwrap_or(false);
                if let Some(entry) = self.cookie_vars.get_mut(&var) {
                    *entry = secure;
                }
            }
            "setString" | "setInt" | "setLong" | "setBytes" | "setNString" => {
                // Parameter binding on a PreparedStatement: nothing to do,
                // but the call must not taint its receiver.
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Expression evaluation
    // ------------------------------------------------------------------

    fn eval(&self, expr: &AstNode) -> bool {
        match expr.kind() {
            NodeKind::StringLiteral => false,
            NodeKind::Identifier => {
                self.tainted.contains(expr.text())
                    || self
                        .slots
                        .get(expr.text())
                        .is_some_and(|slots| slots.iter().any(|s| *s))
            }
            NodeKind::Call => self.eval_call(expr),
            _ => {
                if COND_KINDS.iter().any(|k| is_other(expr, k)) {
                    self.eval_conditional(expr)
                } else {
                    // Conservative join over sub-expressions: casts, array
                    // accesses, concatenations, initializers, …
                    expr.children().iter().any(|c| self.eval(c))
                }
            }
        }
    }

    fn eval_call(&self, expr: &AstNode) -> bool {
        let Some(call) = split_call(expr) else {
            return expr.children().iter().any(|c| self.eval(c));
        };
        if call.is_new {
            // `new StringBuilder(tainted)` carries the taint into the new
            // buffer, so the seeded constructor is handled by the same
            // argument rule as every other construction: only a
            // no-argument builder starts clean.
            return call.args.iter().any(|a| self.eval(a));
        }
        if SANITIZERS.iter().any(|s| call.method == *s) {
            return false;
        }
        if !call.is_new {
            if let Some(outcome) = self.eval_local_method(&call) {
                return outcome.tainted;
            }
        }
        let receiver_taint = call.receiver.map(|r| self.eval(r)).unwrap_or(false);
        match call.method.as_str() {
            // Request-sourced data (and the benchmark's inner-class helper
            // that returns transformed request data).
            m if REQUEST_SOURCES.contains(&m) => true,
            // Positional container access.
            "get" | "elementAt" => {
                // A keyed read resolves exactly; only an unknown key has to
                // fall back to the conservative answer.
                if let Some(key) = call.args.first().and_then(|a| self.literal_of(a)) {
                    if let Some(entries) = call
                        .receiver
                        .filter(|r| *r.kind() == NodeKind::Identifier)
                        .and_then(|r| self.maps.get(r.text()))
                    {
                        return entries.get(&key).copied().unwrap_or(receiver_taint);
                    }
                }
                let slots = call
                    .receiver
                    .filter(|r| *r.kind() == NodeKind::Identifier)
                    .and_then(|r| self.slots.get(r.text()));
                match slots {
                    Some(slots) => match call.args.first().and_then(|a| self.eval_int_text(a.text()))
                    {
                        Some(idx) => slots.get(idx as usize).copied().unwrap_or(receiver_taint),
                        None => slots.iter().any(|s| *s) || receiver_taint,
                    },
                    None => receiver_taint || call.args.iter().any(|a| self.eval(a)),
                }
            }
            "remove" | "removeElement" | "pop" => {
                let slots = call
                    .receiver
                    .filter(|r| *r.kind() == NodeKind::Identifier)
                    .and_then(|r| self.slots.get(r.text()));
                match slots {
                    Some(slots) => match call.args.first().and_then(|a| self.eval_int_text(a.text()))
                    {
                        Some(idx) => slots.get(idx as usize).copied().unwrap_or(receiver_taint),
                        None => slots.iter().any(|s| *s) || receiver_taint,
                    },
                    None => receiver_taint,
                }
            }
            "add" | "append" | "push" => {
                let slots_taint = call
                    .receiver
                    .filter(|r| *r.kind() == NodeKind::Identifier)
                    .and_then(|r| self.slots.get(r.text()))
                    .map(|slots| slots.iter().any(|s| *s))
                    .unwrap_or(false);
                slots_taint || call.args.iter().any(|a| self.eval(a))
            }
            // Identity-ish helpers: the result carries whatever went in.
            // The OWASP Benchmark's `Thing1.doSomething(x)` / `Thing2`
            // helper is exactly this, so propagating the argument is what
            // makes `thing.doSomething(param)` tainted while leaving
            // `thing.doSomething("barbarians_at_the_gate")` clean.
            "toString" | "substring" | "trim" | "replace" | "replaceAll" | "concat" | "intern"
            | "toLowerCase" | "toUpperCase" | "split" | "join" | "format" | "valueOf" | "doSomething" => {
                let slots_taint = call
                    .receiver
                    .filter(|r| *r.kind() == NodeKind::Identifier)
                    .and_then(|r| self.slots.get(r.text()))
                    .map(|slots| slots.iter().any(|s| *s))
                    .unwrap_or(false);
                slots_taint || receiver_taint || call.args.iter().any(|a| self.eval(a))
            }
            _ => receiver_taint || call.args.iter().any(|a| self.eval(a)),
        }
    }

    /// Taint *and encoding* of a call to a method declared in this same
    /// file, answered by running that method's own value flow with the
    /// arguments bound to its parameters. This is what tells apart the two
    /// halves of the OWASP inner-class family: `doSomething(param)` chains
    /// the request data through and comes back tainted, while a body that
    /// ignores its parameter and returns a constant comes back clean — and
    /// a body that only *encodes* its parameter comes back encoded, not
    /// clean, so the trust-boundary status survives the call.
    ///
    /// `None` when the call is not to a resolvable same-file method, or
    /// when that method is already being expanded further up the path (see
    /// [`Flow::inlining`]); the caller then falls back to argument
    /// propagation, which is also what makes a recursive helper terminate.
    fn eval_local_method(&self, call: &CallParts<'_>) -> Option<MethodOutcome> {
        let def = self.methods.get(&call.method)?;
        if call.args.len() != def.params.len() || self.inlining.contains(&call.method) {
            return None;
        }
        let inlining: Inlining =
            Arc::new(self.inlining.iter().cloned().chain([call.method.clone()]).collect());
        let mut pass = Pass::new(self.methods.clone(), inlining);
        for (param, arg) in def.params.iter().zip(&call.args) {
            if self.eval(arg) {
                pass.flow.tainted.insert(param.clone());
            } else if self.encodedness(arg) {
                // The encoded-but-unvalidated status crosses the call
                // boundary with the argument: a helper that returns its
                // parameter still returns request-derived data.
                pass.flow.encoded.insert(param.clone());
            }
        }
        pass.walk(&def.body, false);

        let returned = def
            .body
            .descendants()
            .filter(|n| is_other(n, RETURN_KIND))
            .filter_map(|r| r.children().first())
            .last()?;
        Some(MethodOutcome {
            tainted: pass.flow.eval(returned),
            encoded: pass.flow.encodedness(returned),
        })
    }

    /// The char value of `expr` when statically known. Beyond a char
    /// literal, this covers `literal.charAt(folded_index)` — the shape the
    /// OWASP Benchmark uses to pick a `switch` arm from a constant string.
    fn eval_char(&self, expr: &AstNode) -> Option<char> {
        if let Some(c) = unquote_char(expr.text()) {
            return Some(c);
        }
        // `switch (t)` keeps its parentheses as a node, so look through
        // them to reach the selector itself.
        if is_other(expr, PAREN_KIND) {
            let inner = expr.children().first()?;
            return self.eval_char(inner);
        }
        if *expr.kind() == NodeKind::Identifier {
            return self.chars.get(expr.text()).copied();
        }
        let call = split_call(expr)?;
        if call.method != "charAt" {
            return None;
        }
        let text = self.literal_of(call.receiver?)?;
        let index = self.eval_int_text(call.args.first()?.text())? as usize;
        text.chars().nth(index)
    }

    fn eval_conditional(&self, expr: &AstNode) -> bool {
        let children = expr.children();
        if children.len() < 3 {
            return children.iter().any(|c| self.eval(c));
        }
        match self.eval_int_text(children[0].text()) {
            Some(0) => self.eval(&children[2]),
            Some(_) => self.eval(&children[1]),
            None => self.eval(&children[1]) || self.eval(&children[2]),
        }
    }

    // ------------------------------------------------------------------
    // Constant folding (integer/boolean expressions, textual — the neutral
    // AST drops anonymous operator tokens)
    // ------------------------------------------------------------------

    /// Evaluates `source` as an integer/boolean expression with the known
    /// integer variables. Returns `None` when not foldable.
    pub fn eval_int_text(&self, source: &str) -> Option<i64> {
        let mut parser = IntParser {
            src: source.as_bytes(),
            pos: 0,
            vars: &self.ints,
        };
        let value = parser.parse_expr()?;
        parser.skip_ws();
        if parser.pos != parser.src.len() {
            return None;
        }
        Some(value)
    }
}

/// Taint of each argument of a `new` construction, in order, so a builder
/// seeded with request data starts out tainted. `None` for anything that
/// is not an argument-bearing construction.
fn c_args_taint(call: &AstNode, flow: &Flow) -> Option<Vec<bool>> {
    let parts = split_call(call)?;
    if !parts.is_new || parts.args.is_empty() {
        return None;
    }
    Some(parts.args.iter().map(|a| flow.eval(a)).collect())
}

fn unquote_char(text: &str) -> Option<char> {
    let t = text.trim();
    t.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))?.chars().next()
}

fn unquote(text: &str) -> String {
    let trimmed = text.trim();
    trimmed
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(trimmed)
        .to_string()
}

struct IntParser<'a> {
    src: &'a [u8],
    pos: usize,
    vars: &'a HashMap<String, i64>,
}

impl IntParser<'_> {
    fn skip_ws(&mut self) {
        while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn eat(&mut self, op: &str) -> bool {
        self.skip_ws();
        if self.src[self.pos..].starts_with(op.as_bytes()) {
            self.pos += op.len();
            true
        } else {
            false
        }
    }

    fn parse_expr(&mut self) -> Option<i64> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<i64> {
        let mut lhs = self.parse_and()?;
        while self.eat("||") {
            let rhs = self.parse_and()?;
            lhs = if lhs != 0 || rhs != 0 { 1 } else { 0 };
        }
        Some(lhs)
    }

    fn parse_and(&mut self) -> Option<i64> {
        let mut lhs = self.parse_cmp()?;
        while self.eat("&&") {
            let rhs = self.parse_cmp()?;
            lhs = if lhs != 0 && rhs != 0 { 1 } else { 0 };
        }
        Some(lhs)
    }

    fn parse_cmp(&mut self) -> Option<i64> {
        let lhs = self.parse_add()?;
        let op = if self.eat(">=") {
            ">="
        } else if self.eat("<=") {
            "<="
        } else if self.eat("==") {
            "=="
        } else if self.eat("!=") {
            "!="
        } else if self.eat(">") {
            ">"
        } else if self.eat("<") {
            "<"
        } else {
            return Some(lhs);
        };
        let rhs = self.parse_add()?;
        Some(match op {
            ">=" => (lhs >= rhs) as i64,
            "<=" => (lhs <= rhs) as i64,
            "==" => (lhs == rhs) as i64,
            "!=" => (lhs != rhs) as i64,
            ">" => (lhs > rhs) as i64,
            _ => (lhs < rhs) as i64,
        })
    }

    fn parse_add(&mut self) -> Option<i64> {
        let mut lhs = self.parse_mul()?;
        loop {
            if self.eat("+") {
                lhs = lhs.checked_add(self.parse_mul()?)?;
            } else if self.eat("-") {
                lhs = lhs.checked_sub(self.parse_mul()?)?;
            } else {
                return Some(lhs);
            }
        }
    }

    fn parse_mul(&mut self) -> Option<i64> {
        let mut lhs = self.parse_unary()?;
        loop {
            if self.eat("*") {
                lhs = lhs.checked_mul(self.parse_unary()?)?;
            } else if self.eat("/") {
                lhs = lhs.checked_div(self.parse_unary()?)?;
            } else if self.eat("%") {
                lhs = lhs.checked_rem(self.parse_unary()?)?;
            } else {
                return Some(lhs);
            }
        }
    }

    fn parse_unary(&mut self) -> Option<i64> {
        if self.eat("!") {
            let v = self.parse_unary()?;
            return Some(if v == 0 { 1 } else { 0 });
        }
        if self.eat("-") {
            return self.parse_unary().map(|v| -v);
        }
        if self.eat("(") {
            let v = self.parse_expr()?;
            if !self.eat(")") {
                return None;
            }
            return Some(v);
        }
        self.skip_ws();
        let start = self.pos;
        while self.pos < self.src.len()
            && (self.src[self.pos].is_ascii_alphanumeric() || self.src[self.pos] == b'_')
        {
            self.pos += 1;
        }
        let token = std::str::from_utf8(&self.src[start..self.pos]).ok()?;
        if token.is_empty() {
            return None;
        }
        match token {
            "true" => Some(1),
            "false" => Some(0),
            _ => {
                if let Ok(n) = token.parse::<i64>() {
                    Some(n)
                } else {
                    self.vars.get(token).copied()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vord_ast::{LanguageIdentifier, SourceFile};
    use vord_rules_engine::AstParser;

    use super::*;

    #[test]
    fn encoded_status_crosses_inlined_helpers() {
        // The OWASP inner-class family: the helper runs the encoder, so
        // the caller's variable must keep the encoded-but-unvalidated
        // status instead of collapsing to plain taint = false.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"v\");\n String bar = new Test().doSomething(param);\n}\n private class Test {\n  public String doSomething(String p) {\n   return org.apache.commons.lang.StringEscapeUtils.escapeHtml(p);\n  }\n }\n}",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_unvalidated_request_data(decl_value(&ast, "bar")));
    }

    #[test]
    fn encoding_a_constant_is_not_unvalidated() {
        // Escaping a clean value does not make it attacker-controlled:
        // only encoding real request data records the encoded status.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String param = \"just a constant\";\n String bar = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_unvalidated_request_data(decl_value(&ast, "bar")));
    }

    #[test]
    fn inline_encoder_call_on_tainted_input_is_unvalidated() {
        // A3: an encoder call evaluated as a plain value expression is
        // still encoded-but-unvalidated request data.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"v\");\n String out = org.apache.commons.lang.StringEscapeUtils.escapeHtml(param);\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        let encoder_call = ast
            .descendants()
            .find(|n| split_call(n).is_some_and(|c| c.method == "escapeHtml"))
            .expect("encoder call");
        assert!(state.is_unvalidated_request_data(encoder_call));
    }

    fn parse(code: &str) -> AstNode {
        let file = SourceFile::new("T.java", code, LanguageIdentifier::java()).unwrap();
        vord_parser_java::JavaParser::new().parse(&file).unwrap()
    }

    fn decl_value<'a>(ast: &'a AstNode, name: &str) -> &'a AstNode {
        for node in ast.descendants() {
            if is_other(node, DECLARATOR_KIND) {
                let children = node.children();
                if !children.is_empty() && children[0].text() == name {
                    return &children[1];
                }
            }
        }
        panic!("no declaration of {name}");
    }

    #[test]
    fn request_parameter_is_tainted() {
        let ast = parse("class T { void f(HttpServletRequest request) { String p = request.getParameter(\"v\"); } }");
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "p")));
    }

    #[test]
    fn taint_flows_through_assignment() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n String q = p;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "q")));
    }

    #[test]
    fn list_slots_resolve_after_remove() {
        // The OWASP "list trick": remove(0) leaves the param at index 0.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n java.util.List<String> l = new java.util.ArrayList<String>();\n l.add(\"safe\");\n l.add(p);\n l.remove(0);\n String bar = l.get(0);\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn list_slots_keep_constants_clean() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n java.util.List<String> l = new java.util.ArrayList<String>();\n l.add(\"safe\");\n l.add(p);\n l.add(\"moresafe\");\n l.remove(0);\n String bar = l.get(1);\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn constant_true_ternary_takes_the_constant_branch() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n int num = 106;\n String bar = (7*18) + num > 200 ? \"always\" : p;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn local_helper_that_ignores_its_argument_is_clean() {
        // The OWASP inner-class family: the helper takes a parameter but
        // returns a constant, so the request data never reaches the sink.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"v\");\n String bar = new Test().doSomething(param);\n}\n private class Test {\n  public String doSomething(String p) {\n   String g = \"barbarians_at_the_gate\";\n   String out = p;\n   String result = g;\n   return result;\n  }\n }\n}",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn local_helper_that_chains_its_argument_is_tainted() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"v\");\n String bar = new Test().doSomething(param);\n}\n private class Test {\n  public String doSomething(String p) {\n   String a = p;\n   StringBuilder b = new StringBuilder(a);\n   return b.toString();\n  }\n }\n}",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn recursive_local_helper_terminates() {
        // Inlining a helper that calls itself must stop at the recursive
        // call rather than expanding forever.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n String out = helper(p);\n}\n String helper(String x) {\n if (x == null) return \"\";\n return helper(x);\n }\n}",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn constant_switch_selects_one_case() {
        // `guess.charAt(1)` on the constant "ABC" is 'B', so the 'A' case
        // — the one that copies request data — is dead code.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n String guess = \"ABC\";\n char t = guess.charAt(1);\n String bar;\n switch (t) {\n  case 'A': bar = p; break;\n  case 'B': bar = \"bob\"; break;\n }\n String out = bar;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn constant_switch_follows_fall_through() {
        // `charAt(2)` is 'C', a bare label that falls into the 'D' group —
        // the one that actually copies request data.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n String guess = \"ABC\";\n char t = guess.charAt(2);\n String bar;\n switch (t) {\n  case 'A': bar = p; break;\n  case 'B': bar = \"bob\"; break;\n  case 'C':\n  case 'D': bar = p; break;\n  default: bar = \"bob\"; break;\n }\n String out = bar;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn constant_switch_default_stays_dead() {
        // 'A' selects the first group, so the tainted `default` arm never
        // runs even though it is the fall-through target of nothing.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n String guess = \"ABC\";\n char t = guess.charAt(0);\n String bar;\n switch (t) {\n  case 'A': bar = \"safe\"; break;\n  default: bar = p; break;\n }\n String out = bar;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn unfoldable_switch_keeps_every_case_reachable() {
        let ast = parse(
            "class T { void f(HttpServletRequest request, char c) {\n String p = request.getParameter(\"v\");\n String bar;\n switch (c) {\n  case 'A': bar = p; break;\n  case 'B': bar = \"bob\"; break;\n }\n String out = bar;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn constant_if_takes_the_live_branch() {
        // The statement twin of the ternary above: a condition that folds
        // to true means the `else` arm is dead code. `bar` is declared
        // uninitialized first, as the benchmark writes it.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n int num = 86;\n String bar;\n if ((7*42) - num > 200) bar = \"always\";\n else bar = p;\n String out = bar;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn constant_if_false_skips_the_then_branch() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n int num = 106;\n String bar;\n if ((7*42) - num > 200) bar = p;\n else bar = \"always\";\n String out = bar;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "out")));
    }

    #[test]
    fn null_guard_does_not_launder_request_data() {
        // `if (param == null) param = "";` is a null check, not a
        // sanitizer — the fall-through path keeps the request data.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String param = request.getParameter(\"v\");\n if (param == null) param = \"\";\n String sql = \"{call \" + param + \"}\";\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "sql")));
    }

    #[test]
    fn unknown_ternary_joins_both_branches() {
        let ast = parse(
            "class T { void f(HttpServletRequest request, boolean c) {\n String p = request.getParameter(\"v\");\n String bar = c ? \"safe\" : p;\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn sanitizer_cleanses() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n String q = org.owasp.esapi.ESAPI.encoder().encodeForHTML(p);\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "q")));
    }

    #[test]
    fn string_builder_append_propagates() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n StringBuilder sb = new StringBuilder();\n sb.append(\"x\");\n sb.append(p);\n String bar = sb.toString();\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn seeded_string_builder_carries_its_argument() {
        // `new StringBuilder(tainted)` is a tainted builder, so a later
        // append and toString stay tainted without any further evidence.
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n StringBuilder sb = new StringBuilder(p);\n String bar = sb.append(\"x\").toString();\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn keyed_map_resolves_by_key() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n String p = request.getParameter(\"v\");\n java.util.HashMap<String,Object> m = new java.util.HashMap<String,Object>();\n m.put(\"safe\", \"a\");\n m.put(\"vector\", p);\n String bar = (String)m.get(\"vector\");\n String safe = (String)m.get(\"safe\");\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "bar")));
        assert!(!state.is_tainted(decl_value(&ast, "safe")));
    }

    #[test]
    fn string_builder_constants_stay_clean() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n StringBuilder sb = new StringBuilder();\n sb.append(\"x\");\n String bar = sb.toString();\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(!state.is_tainted(decl_value(&ast, "bar")));
    }

    #[test]
    fn for_each_loop_variable_carries_taint() {
        let ast = parse(
            "class T { void f(HttpServletRequest request) {\n javax.servlet.http.Cookie[] cs = request.getCookies();\n for (javax.servlet.http.Cookie c : cs) {\n   String v = c.getValue();\n }\n} }",
        );
        let state = ServletTaint::analyze(&ast);
        assert!(state.is_tainted(decl_value(&ast, "v")));
    }

    #[test]
    fn split_call_finds_receiver_and_method() {
        let ast = parse("class T { void f() { response.getWriter().printf(a, b); } }");
        let calls: Vec<_> = ast
            .descendants()
            .filter(|n| *n.kind() == NodeKind::Call)
            .collect();
        let outer = calls
            .iter()
            .find(|c| split_call(c).is_some_and(|p| p.method == "printf"))
            .expect("printf call");
        let parts = split_call(outer).unwrap();
        assert_eq!(parts.method, "printf");
        assert_eq!(parts.args.len(), 2);
        assert_eq!(parts.receiver_text, "response.getWriter()");
    }

    #[test]
    fn string_literal_vars_resolve_for_hash_rule() {
        let ast = parse(
            "class T { void f() { String algorithm = \"SHA-256\"; java.security.MessageDigest md = java.security.MessageDigest.getInstance(algorithm); } }",
        );
        let state = ServletTaint::analyze(&ast);
        assert_eq!(
            state.literal_of(decl_value(&ast, "algorithm")).as_deref(),
            Some("SHA-256")
        );
    }
}





