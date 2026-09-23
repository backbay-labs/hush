use hushspec::{
    Actor, CallbackSink, CompiledPolicy, Decision, EvaluationAction, HushGuard, HushSpec, Policy,
    resolve_from_path, validate,
};
use std::{
    fs,
    io::Write,
    sync::{Arc, Mutex},
};
mod trust;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "policy.yaml".into());
    let document = HushSpec::parse(&fs::read_to_string(&policy_path)?)?;
    assert!(validate(&document).is_valid());
    let resolved = resolve_from_path(&policy_path)?;
    let compiled = CompiledPolicy::compile(&resolved)?;
    trust::check_trust(&policy_path, &resolved)?;
    let action = |target: &str| EvaluationAction {
        action_type: "tool_call".into(),
        target: Some(target.into()),
        ..Default::default()
    };
    assert_eq!(
        compiled.evaluate(&action("search")).decision,
        Decision::Allow
    );
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let builder = || {
        let recorded = Arc::clone(&receipts);
        HushGuard::builder()
            .actor(Actor {
                agent_id: Some("docs-agent".into()),
                session_id: Some("docs-session".into()),
                principal: Some("docs-user".into()),
                runtime: Some("docs/1.0.0".into()),
            })
            .sink(Box::new(CallbackSink::new(move |receipt| {
                recorded.lock().unwrap().push(receipt.clone());
                Ok(())
            })))
    };
    let guard = builder().build_from_policy(Policy::from_path(&policy_path)?)?;
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("effect.txt");
    let dispatches = std::cell::Cell::new(0);
    let dispatch = |guard: &HushGuard, tool: &str| -> Result<bool, std::io::Error> {
        if !guard.check(&action(tool)).allowed() {
            return Ok(false);
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)?;
        file.write_all(b"confirmed once\n")?;
        dispatches.set(dispatches.get() + 1);
        Ok(true)
    };
    assert!(!dispatch(&guard, "deploy")?);
    assert!(!dispatch(&guard, "write_file")?);
    assert_eq!(dispatches.get(), 0);
    assert!(!output.exists());
    let confirmed = builder()
        .on_warn(|_, _| true)
        .build_from_policy(Policy::from_path(&policy_path)?)?;
    assert!(dispatch(&confirmed, "write_file")?);
    assert_eq!(dispatches.get(), 1);
    assert_eq!(fs::read_to_string(output)?, "confirmed once\n");
    let receipts = receipts.lock().unwrap();
    let last = receipts.last().unwrap();
    assert_eq!(
        last.enforcement.outcome,
        hushspec::EnforcementOutcome::Confirmed
    );
    assert_eq!(
        last.actor.as_ref().unwrap().agent_id.as_deref(),
        Some("docs-agent")
    );
    assert!(HushSpec::parse("hushspec: \"1.0.0\"\nunknown_rule: true\n").is_err());
    println!(
        "PASS: deny=0 dispatches; unconfirmed warn=0; confirmed warn=1; invalid policy refused"
    );
    Ok(())
}
