//! `vord agent tui` — a live view onto a headless `vord agent run` (roadmap
//! A6, deliberately last: "a headless `vord agent run --task` that is
//! scriptable and CI-usable is worth more than a chat interface, and it is
//! what the swarm in workstream B drives").
//!
//! This module renders; it never decides. It attaches an
//! [`vord_agent::Observer`] to the same [`vord_cli::agent::run_with_observer`]
//! headless entry point `vord agent run` uses, so watching a run can never
//! change what it does — the type signature of
//! [`vord_agent::observer::Observer::on_event`] returns nothing for the loop
//! to branch on, and this file adds no second path to disk. Quitting the TUI
//! (`q`/`Esc`/`Ctrl-C`) detaches rather than cancels: the run keeps going
//! headless and reports through the same `vord agent: ...` line a
//! non-interactive run would, because a spectator leaving the room must not
//! stop the game.

use std::io;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use tokio::sync::mpsc;

use vord_agent::RunOutcome;
use vord_agent::observer::{AgentEvent, Observer};

/// Forwards every event across a channel — the only thing standing between
/// the async runtime loop and the render loop, both of which need to keep
/// moving independently.
struct ChannelObserver {
    tx: mpsc::UnboundedSender<AgentEvent>,
}

impl Observer for ChannelObserver {
    fn on_event(&self, event: AgentEvent) {
        // A closed receiver means the UI already detached; the run itself
        // does not care and must keep going regardless.
        let _ = self.tx.send(event);
    }
}

/// What's on screen, rebuilt as events arrive. Deliberately not the model's
/// own `Transcript` — that's context-window material; this is what a human
/// watching wants: recent activity, current turn, and the run's status.
struct UiState {
    task: String,
    scope: String,
    turn: u32,
    log: Vec<Line<'static>>,
    status: String,
    outcome: Option<RunOutcome>,
}

impl UiState {
    fn new(task: &str, scope: &str) -> Self {
        Self {
            task: task.to_string(),
            scope: scope.to_string(),
            turn: 0,
            log: Vec::new(),
            status: "starting…".to_string(),
            outcome: None,
        }
    }

    fn push(&mut self, style: Style, text: impl Into<String>) {
        self.log.push(Line::styled(text.into(), style));
    }

    fn apply(&mut self, event: AgentEvent) {
        match event {
            AgentEvent::TurnStarted { turn } => {
                self.turn = turn;
                self.status = format!("turn {turn} — waiting on the model");
                self.push(
                    Style::default().add_modifier(Modifier::BOLD),
                    format!("── turn {turn} ──"),
                );
            }
            AgentEvent::ModelResponded { turn } => {
                if let Some(text) = turn.text.filter(|t| !t.is_empty()) {
                    self.push(
                        Style::default().fg(Color::Cyan),
                        format!("model: {}", truncate(&text, 300)),
                    );
                }
                if turn.calls.is_empty() {
                    self.status = "model claims completion — adjudicating".to_string();
                }
            }
            AgentEvent::ToolCallStarted { call } => {
                self.status = format!("running `{}`", call.name);
                self.push(
                    Style::default().fg(Color::Yellow),
                    format!(
                        "  → {} {}",
                        call.name,
                        truncate(&call.input.to_string(), 120)
                    ),
                );
            }
            AgentEvent::ToolCallFinished { result } => {
                let style = if result.is_error {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::Green)
                };
                let marker = if result.is_error { "✗" } else { "✓" };
                self.push(
                    style,
                    format!("  {marker} {}", truncate(&result.content, 200)),
                );
            }
            AgentEvent::WriteJudged { path, evaluation } => {
                if evaluation.is_denied() {
                    self.push(
                        Style::default().fg(Color::Red),
                        format!("  ⛔ write denied: {path}"),
                    );
                } else {
                    self.push(
                        Style::default().fg(Color::Green),
                        format!("  ✅ write allowed: {path}"),
                    );
                }
            }
            AgentEvent::Adjudicated { completion } => {
                let done = completion.is_done();
                let style = if done {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Yellow)
                };
                self.push(
                    style,
                    format!("⚖ {}", truncate(&completion.describe(), 300)),
                );
            }
            AgentEvent::Finished { outcome } => {
                self.status = outcome.describe();
                self.push(
                    Style::default().add_modifier(Modifier::BOLD),
                    format!("== {} ==", outcome.describe()),
                );
                self.outcome = Some(outcome);
            }
        }
    }
}

fn truncate(text: &str, max: usize) -> String {
    let collapsed: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        collapsed
    } else {
        format!("{}…", collapsed.chars().take(max).collect::<String>())
    }
}

/// RAII terminal setup/teardown, so every early return (an error, a quit
/// key) restores the user's shell instead of leaving it in raw mode.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Runs the session with a live terminal view attached. `run` builds the
/// runtime exactly as headless `vord agent run` does — this only supplies an
/// observer and a render loop around it.
///
/// Returns the final [`RunOutcome`] whether the user watched it happen or
/// quit early — quitting detaches the view, not the run (see this module's
/// docs).
pub async fn run(
    root: &std::path::Path,
    args: vord_cli::agent::AgentArgs,
) -> anyhow::Result<RunOutcome> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let task = args.task.clone();
    let scope = args.scope.clone();
    let root = root.to_path_buf();
    let handle = tokio::spawn(async move {
        vord_cli::agent::run_with_observer(&root, args, ChannelObserver { tx }).await
    });

    let mut state = UiState::new(&task, &scope);
    let guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut detached = false;

    loop {
        terminal.draw(|frame| draw(frame, &state))?;

        // Once the run has a final outcome there is nothing left to watch
        // for — just wait for the human to dismiss the summary screen.
        if state.outcome.is_some() {
            if event::poll(Duration::from_millis(80))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        break;
                    }
                }
            }
            continue;
        }

        // A short poll keeps the UI responsive to both new events and key
        // presses without busy-spinning a core; the multi-threaded tokio
        // runtime means this blocking poll never stalls the spawned run.
        match rx.try_recv() {
            Ok(event) => {
                state.apply(event);
                continue;
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                // The run finished and dropped its observer without a final
                // `Finished` event reaching us — should not happen, but a
                // closed channel must still end the loop rather than spin.
                break;
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
        }

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let quits = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                        || (key.code == KeyCode::Char('c')
                            && key.modifiers.contains(KeyModifiers::CONTROL));
                    if quits {
                        detached = true;
                        break;
                    }
                }
            }
        }
    }

    drop(terminal);
    drop(guard);

    if detached {
        println!("vord agent tui: detached — the run continues headless.");
    }
    handle
        .await
        .map_err(|e| anyhow::anyhow!("agent task panicked: {e}"))?
}

fn draw(frame: &mut ratatui::Frame, state: &UiState) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);

    draw_header(frame, chunks[0], state);
    draw_log(frame, chunks[1], state);
    draw_footer(frame, chunks[2], state);
}

fn draw_header(frame: &mut ratatui::Frame, area: Rect, state: &UiState) {
    let text = vec![Line::from(vec![
        Span::styled("task: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(state.task.clone()),
        Span::raw("  "),
        Span::styled("scope: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(state.scope.clone()),
        Span::raw("  "),
        Span::styled("turn: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(state.turn.to_string()),
    ])];
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("vord agent")),
        area,
    );
}

fn draw_log(frame: &mut ratatui::Frame, area: Rect, state: &UiState) {
    let height = area.height.saturating_sub(2) as usize;
    let start = state.log.len().saturating_sub(height);
    let items: Vec<ListItem> = state.log[start..]
        .iter()
        .cloned()
        .map(ListItem::new)
        .collect();
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title("activity")),
        area,
    );
}

fn draw_footer(frame: &mut ratatui::Frame, area: Rect, state: &UiState) {
    let style = match &state.outcome {
        Some(RunOutcome::Completed { .. }) => Style::default().fg(Color::Green),
        Some(_) => Style::default().fg(Color::Red),
        None => Style::default(),
    };
    let hint = if state.outcome.is_some() {
        "press any key to exit"
    } else {
        "q / Esc / Ctrl-C to detach (the run keeps going)"
    };
    let text = Line::from(vec![
        Span::styled(state.status.clone(), style),
        Span::raw("   "),
        Span::styled(hint, Style::default().fg(Color::DarkGray)),
    ]);
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(Block::default().borders(Borders::ALL)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use vord_agent::budget::Exhaustion;
    use vord_agent::completion::Completion;
    use vord_agent::session::{AssistantTurn, TokenUsage, ToolCall, ToolResult};

    #[test]
    fn truncate_collapses_whitespace_and_leaves_short_text_alone() {
        assert_eq!(truncate("a  b\nc", 100), "a b c");
    }

    #[test]
    fn truncate_cuts_long_text_and_marks_it() {
        let long = "x".repeat(50);
        let truncated = truncate(&long, 10);
        assert_eq!(
            truncated.chars().count(),
            11,
            "10 chars plus the ellipsis marker"
        );
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn a_turn_started_event_updates_the_current_turn_and_logs_it() {
        let mut state = UiState::new("fix it", ".");
        state.apply(AgentEvent::TurnStarted { turn: 3 });
        assert_eq!(state.turn, 3);
        assert!(state.log.last().is_some());
    }

    #[test]
    fn model_text_is_logged_but_an_empty_response_adds_nothing() {
        let mut state = UiState::new("fix it", ".");
        state.apply(AgentEvent::ModelResponded {
            turn: AssistantTurn {
                text: None,
                calls: vec![],
                usage: TokenUsage::default(),
            },
        });
        assert!(state.log.is_empty());

        state.apply(AgentEvent::ModelResponded {
            turn: AssistantTurn {
                text: Some("done".into()),
                calls: vec![],
                usage: TokenUsage::default(),
            },
        });
        assert_eq!(state.log.len(), 1);
    }

    #[test]
    fn a_tool_call_and_its_result_are_both_logged() {
        let mut state = UiState::new("fix it", ".");
        state.apply(AgentEvent::ToolCallStarted {
            call: ToolCall {
                id: "1".into(),
                name: "read".into(),
                input: serde_json::json!({"path": "a.rs"}),
            },
        });
        state.apply(AgentEvent::ToolCallFinished {
            result: ToolResult::ok("1", "contents"),
        });
        assert_eq!(state.log.len(), 2);
    }

    #[test]
    fn a_finished_event_records_the_outcome() {
        let mut state = UiState::new("fix it", ".");
        assert!(state.outcome.is_none());
        state.apply(AgentEvent::Finished {
            outcome: RunOutcome::BudgetExhausted {
                turns: 2,
                exhaustion: Exhaustion::Turns { limit: 2 },
            },
        });
        assert!(matches!(
            state.outcome,
            Some(RunOutcome::BudgetExhausted { .. })
        ));
    }

    #[test]
    fn adjudication_is_logged_regardless_of_verdict() {
        let mut state = UiState::new("fix it", ".");
        state.apply(AgentEvent::Adjudicated {
            completion: Completion::Done,
        });
        assert_eq!(state.log.len(), 1);
    }
}
