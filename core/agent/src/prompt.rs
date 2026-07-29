//! The agent's constitution.
//!
//! Pure text, kept out of the runtime so it can be asserted on: the prompt is
//! the only place the model learns that its writes are judged by something it
//! cannot argue with, and a regression here is a behaviour regression.

use crate::tools::{tool_specs, CommandAllowlist};

/// The system prompt. States the two rules that make this runtime different
/// from every other coding agent — the policy decides whether a write lands,
/// and the analyzer decides whether the task is done — because a model that
/// does not know it is being judged spends its turns arguing with the judge.
pub fn system_prompt(allowlist: &CommandAllowlist) -> String {
    let tools: Vec<&str> = tool_specs().iter().map(|spec| spec.name.as_str()).collect();
    format!(
        "You are yunq agent: a coding agent that edits a repository under a policy you do not control.\n\
         \n\
         Two rules govern this session, and neither is negotiable:\n\
         1. Every `write` and `edit` is evaluated by yunq's Agent Permission Policy before it \
         reaches disk. A denied write does not happen. You will be told exactly which rule denied \
         it and why; fix the cause rather than retrying or relocating the same code.\n\
         2. You do not decide when the task is done. When you stop calling tools, yunq re-runs its \
         analyzer and compares the result to the baseline it took before you started. If the target \
         issue is still there, or you introduced a finding that was not there before, you will be \
         told and the session continues.\n\
         \n\
         Your tools are exactly: {tools}. There is no shell. `run` executes one allow-listed \
         program with arguments — no pipes, no chaining, no redirection. Allowed programs: {allowed}.\n\
         \n\
         Work in small, verifiable steps. Read before you write. Prefer `edit` over `write` for an \
         existing file. When you believe the task is complete, stop calling tools and say what you \
         changed.",
        tools = tools.join(", "),
        allowed = allowlist.programs().join(", "),
    )
}

/// The opening user turn: the task, and the scope the analyzer will judge it
/// against, so the model knows which tree its regressions will be measured in.
pub fn task_prompt(task: &str, scope: &str, target_rule: Option<&str>) -> String {
    let mut out = format!("Task: {task}\n\nThe analyzer's baseline was taken over `{scope}`.");
    if let Some(rule) = target_rule {
        out.push_str(&format!(
            "\n\nThis task is complete only when `{rule}` no longer fires anywhere in that scope."
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_prompt_names_every_tool_the_runtime_will_execute() {
        let prompt = system_prompt(&CommandAllowlist::default());
        for spec in tool_specs() {
            assert!(prompt.contains(spec.name.as_str()), "{} is not advertised", spec.name.as_str());
        }
    }

    #[test]
    fn the_system_prompt_states_that_writes_are_judged_before_they_land() {
        let prompt = system_prompt(&CommandAllowlist::default());
        assert!(prompt.contains("before it reaches disk"));
        assert!(prompt.contains("A denied write does not happen."));
    }

    #[test]
    fn the_system_prompt_states_that_the_model_does_not_decide_completion() {
        assert!(system_prompt(&CommandAllowlist::default()).contains("You do not decide when the task is done."));
    }

    #[test]
    fn the_system_prompt_lists_the_actual_allowlist_not_a_generic_one() {
        let prompt = system_prompt(&CommandAllowlist::new(["just"]));
        assert!(prompt.contains("Allowed programs: just."));
        assert!(!prompt.contains("cargo"));
    }

    #[test]
    fn the_system_prompt_denies_the_existence_of_a_shell() {
        assert!(system_prompt(&CommandAllowlist::default()).contains("There is no shell."));
    }

    #[test]
    fn the_task_prompt_carries_the_scope_the_baseline_was_taken_over() {
        let prompt = task_prompt("remove the eval call", "src", None);
        assert!(prompt.contains("remove the eval call"));
        assert!(prompt.contains("`src`"));
    }

    #[test]
    fn a_targeted_task_states_the_rule_that_must_stop_firing() {
        let prompt = task_prompt("fix it", ".", Some("owasp:eval-usage"));
        assert!(prompt.contains("`owasp:eval-usage` no longer fires"));
    }

    #[test]
    fn an_untargeted_task_makes_no_claim_about_a_rule() {
        assert!(!task_prompt("fix it", ".", None).contains("no longer fires"));
    }
}
