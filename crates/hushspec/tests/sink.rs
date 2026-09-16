use std::sync::{Arc, Mutex};

use hushspec::evaluate::Decision;
use hushspec::receipt::{
    ActionSummary, DecisionReceipt, PolicySummary, RuleEvaluation, RuleOutcome,
};
use hushspec::sink::{
    CallbackSink, FileReceiptSink, FilteredSink, MultiSink, NullSink, ReceiptSink, SinkError,
};

fn make_receipt(decision: Decision) -> DecisionReceipt {
    DecisionReceipt {
        receipt_id: "test-receipt-001".to_string(),
        timestamp: "2026-03-15T00:00:00.000Z".to_string(),
        hushspec_version: "0.1.0".to_string(),
        action: ActionSummary {
            action_type: "tool_call".to_string(),
            target: Some("test_tool".to_string()),
            content_redacted: false,
        },
        decision,
        matched_rule: Some("rules.tool_access.allow".to_string()),
        reason: Some("tool is explicitly allowed".to_string()),
        rule_trace: vec![RuleEvaluation {
            rule_block: "tool_access".to_string(),
            outcome: RuleOutcome::Allow,
            matched_rule: Some("rules.tool_access.allow".to_string()),
            reason: Some("tool is explicitly allowed".to_string()),
            evaluated: true,
        }],
        policy: PolicySummary {
            name: Some("test-policy".to_string()),
            version: "0.1.0".to_string(),
            content_hash: "abc123".to_string(),
        },
        origin_profile: None,
        posture: None,
        enforcement: None,
        evaluation_duration_us: 42,
    }
}

// --- FileReceiptSink ---

#[test]
fn file_sink_writes_json_lines() {
    let dir = std::env::temp_dir().join(format!("hushspec_sink_test_{}", std::process::id()));
    let path = dir.join("receipts.jsonl");
    std::fs::create_dir_all(&dir).unwrap();

    let sink = FileReceiptSink::new(&path);
    let r1 = make_receipt(Decision::Allow);
    let r2 = make_receipt(Decision::Deny);

    sink.send(&r1).unwrap();
    sink.send(&r2).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 JSON lines");

    // Each line should parse as valid JSON.
    let parsed1: DecisionReceipt = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed1.receipt_id, "test-receipt-001");

    let parsed2: DecisionReceipt = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(parsed2.decision, Decision::Deny);

    // Cleanup.
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_sink_appends_not_overwrites() {
    let dir = std::env::temp_dir().join(format!("hushspec_sink_append_{}", std::process::id()));
    let path = dir.join("receipts.jsonl");
    std::fs::create_dir_all(&dir).unwrap();

    let sink = FileReceiptSink::new(&path);
    let receipt = make_receipt(Decision::Allow);

    sink.send(&receipt).unwrap();
    sink.send(&receipt).unwrap();
    sink.send(&receipt).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3, "expected 3 lines after 3 sends");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_sink_handles_concurrent_writers() {
    // 8 threads x 200 receipts through one shared sink. If `FileReceiptSink`
    // ever interleaves writes (e.g. a future refactor batches multiple
    // `write()` syscalls per `send()`), lines get corrupted (a line that
    // fails to parse as JSON, or a line count short of 1600 because two
    // writers' bytes landed in the same line).
    const THREADS: usize = 8;
    const PER_THREAD: usize = 200;

    let dir = std::env::temp_dir().join(format!("hushspec_sink_concurrent_{}", std::process::id()));
    let path = dir.join("receipts.jsonl");
    std::fs::create_dir_all(&dir).unwrap();

    let sink = Arc::new(FileReceiptSink::new(&path));
    let handles: Vec<_> = (0..THREADS)
        .map(|thread_id| {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                for i in 0..PER_THREAD {
                    let decision = if i % 2 == 0 {
                        Decision::Allow
                    } else {
                        Decision::Deny
                    };
                    let mut receipt = make_receipt(decision);
                    receipt.receipt_id = format!("t{thread_id}-r{i}");
                    sink.send(&receipt)
                        .expect("concurrent send should not error");
                }
            })
        })
        .collect();

    for handle in handles {
        handle.join().expect("writer thread should not panic");
    }

    let content = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(
        lines.len(),
        THREADS * PER_THREAD,
        "expected {} lines from {THREADS} threads x {PER_THREAD} receipts; \
         a lower count means concurrent writes interleaved and merged lines",
        THREADS * PER_THREAD
    );

    let mut seen = std::collections::HashSet::new();
    for (index, line) in lines.iter().enumerate() {
        let parsed: DecisionReceipt = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("line {index} is not valid JSON ({error}): {line:?}"));
        assert!(
            seen.insert(parsed.receipt_id.clone()),
            "duplicate receipt_id {} at line {index}: writers must not clobber each other's lines",
            parsed.receipt_id
        );
    }
    assert_eq!(seen.len(), THREADS * PER_THREAD);

    let _ = std::fs::remove_dir_all(&dir);
}

// --- FilteredSink ---

#[test]
fn filtered_sink_deny_only_forwards_deny() {
    let collected = Arc::new(Mutex::new(Vec::new()));
    let collected_clone = Arc::clone(&collected);

    let callback = CallbackSink::new(move |receipt: &DecisionReceipt| {
        collected_clone.lock().unwrap().push(receipt.decision);
        Ok(())
    });

    let filtered = FilteredSink::deny_only(Box::new(callback));

    filtered.send(&make_receipt(Decision::Allow)).unwrap();
    filtered.send(&make_receipt(Decision::Warn)).unwrap();
    filtered.send(&make_receipt(Decision::Deny)).unwrap();
    filtered.send(&make_receipt(Decision::Allow)).unwrap();
    filtered.send(&make_receipt(Decision::Deny)).unwrap();

    let decisions = collected.lock().unwrap();
    assert_eq!(
        decisions.len(),
        2,
        "expected only 2 deny receipts forwarded"
    );
    assert_eq!(decisions[0], Decision::Deny);
    assert_eq!(decisions[1], Decision::Deny);
}

#[test]
fn filtered_sink_allow_only() {
    let collected = Arc::new(Mutex::new(Vec::new()));
    let collected_clone = Arc::clone(&collected);

    let callback = CallbackSink::new(move |receipt: &DecisionReceipt| {
        collected_clone.lock().unwrap().push(receipt.decision);
        Ok(())
    });

    let filtered = FilteredSink::new(Box::new(callback), vec![Decision::Allow]);

    filtered.send(&make_receipt(Decision::Allow)).unwrap();
    filtered.send(&make_receipt(Decision::Deny)).unwrap();
    filtered.send(&make_receipt(Decision::Warn)).unwrap();

    let decisions = collected.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0], Decision::Allow);
}

// --- MultiSink ---

#[test]
fn multi_sink_sends_to_all() {
    let count1 = Arc::new(Mutex::new(0u32));
    let count2 = Arc::new(Mutex::new(0u32));
    let c1 = Arc::clone(&count1);
    let c2 = Arc::clone(&count2);

    let sink1 = CallbackSink::new(move |_: &DecisionReceipt| {
        *c1.lock().unwrap() += 1;
        Ok(())
    });
    let sink2 = CallbackSink::new(move |_: &DecisionReceipt| {
        *c2.lock().unwrap() += 1;
        Ok(())
    });

    let multi = MultiSink::new(vec![Box::new(sink1), Box::new(sink2)]);
    let receipt = make_receipt(Decision::Allow);

    multi.send(&receipt).unwrap();
    multi.send(&receipt).unwrap();

    assert_eq!(*count1.lock().unwrap(), 2);
    assert_eq!(*count2.lock().unwrap(), 2);
}

#[test]
fn multi_sink_continues_after_error() {
    let count = Arc::new(Mutex::new(0u32));
    let c = Arc::clone(&count);

    let failing_sink = CallbackSink::new(|_: &DecisionReceipt| {
        Err(SinkError::Io(std::io::Error::other("test error")))
    });

    let counting_sink = CallbackSink::new(move |_: &DecisionReceipt| {
        *c.lock().unwrap() += 1;
        Ok(())
    });

    // Failing sink is first, counting sink is second.
    let multi = MultiSink::new(vec![Box::new(failing_sink), Box::new(counting_sink)]);
    let receipt = make_receipt(Decision::Allow);

    // Should return an error (from first sink) but second sink still runs.
    let result = multi.send(&receipt);
    assert!(result.is_err());
    assert_eq!(
        *count.lock().unwrap(),
        1,
        "second sink should still execute"
    );
}

#[test]
fn multi_sink_preserves_receipt_order() {
    let collected1 = Arc::new(Mutex::new(Vec::new()));
    let collected2 = Arc::new(Mutex::new(Vec::new()));
    let c1 = Arc::clone(&collected1);
    let c2 = Arc::clone(&collected2);

    let sink1 = CallbackSink::new(move |receipt: &DecisionReceipt| {
        c1.lock().unwrap().push(receipt.receipt_id.clone());
        Ok(())
    });
    let sink2 = CallbackSink::new(move |receipt: &DecisionReceipt| {
        c2.lock().unwrap().push(receipt.receipt_id.clone());
        Ok(())
    });
    let multi = MultiSink::new(vec![Box::new(sink1), Box::new(sink2)]);

    let mut receipts = Vec::new();
    for i in 0..5 {
        let mut receipt = make_receipt(if i % 2 == 0 {
            Decision::Allow
        } else {
            Decision::Deny
        });
        receipt.receipt_id = format!("receipt-{i}");
        receipts.push(receipt);
    }
    for receipt in &receipts {
        multi.send(receipt).unwrap();
    }

    let expected: Vec<String> = receipts.iter().map(|r| r.receipt_id.clone()).collect();
    assert_eq!(
        *collected1.lock().unwrap(),
        expected,
        "sink1 should observe receipts in the order they were sent"
    );
    assert_eq!(
        *collected2.lock().unwrap(),
        expected,
        "sink2 should observe receipts in the order they were sent"
    );
}

#[test]
fn multi_sink_reports_errors_from_every_failing_inner_sink() {
    // MultiSink's doc comment promises: "Returns the first error but invokes
    // all sinks." Verify both halves: the returned error is sink1's (the
    // first failure), and every sink -- including sink2, which also fails,
    // and sink3, which comes after two failures -- still runs.
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let a1 = Arc::clone(&attempts);
    let a2 = Arc::clone(&attempts);
    let a3 = Arc::clone(&attempts);

    let sink1 = CallbackSink::new(move |_: &DecisionReceipt| {
        a1.lock().unwrap().push("sink1");
        Err(SinkError::Io(std::io::Error::other("sink1 failed")))
    });
    let sink2 = CallbackSink::new(move |_: &DecisionReceipt| {
        a2.lock().unwrap().push("sink2");
        Err(SinkError::Io(std::io::Error::other("sink2 failed")))
    });
    let sink3 = CallbackSink::new(move |_: &DecisionReceipt| {
        a3.lock().unwrap().push("sink3");
        Ok(())
    });

    let multi = MultiSink::new(vec![Box::new(sink1), Box::new(sink2), Box::new(sink3)]);
    let result = multi.send(&make_receipt(Decision::Deny));

    let err = result.expect_err("multi sink should surface an error when any inner sink fails");
    assert!(
        err.to_string().contains("sink1 failed"),
        "expected the first inner sink's error, got: {err}"
    );

    assert_eq!(
        *attempts.lock().unwrap(),
        vec!["sink1", "sink2", "sink3"],
        "MultiSink must invoke every inner sink, even after an earlier one fails"
    );
}

// --- NullSink ---

#[test]
fn null_sink_does_not_crash() {
    let sink = NullSink;
    let receipt = make_receipt(Decision::Allow);

    let result = sink.send(&receipt);
    assert!(result.is_ok());

    // Send multiple times to verify stability.
    sink.send(&make_receipt(Decision::Deny)).unwrap();
    sink.send(&make_receipt(Decision::Warn)).unwrap();
}

// --- CallbackSink ---

#[test]
fn callback_sink_invokes_callback() {
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let receipts_clone = Arc::clone(&receipts);

    let sink = CallbackSink::new(move |receipt: &DecisionReceipt| {
        receipts_clone
            .lock()
            .unwrap()
            .push(receipt.receipt_id.clone());
        Ok(())
    });

    sink.send(&make_receipt(Decision::Allow)).unwrap();
    sink.send(&make_receipt(Decision::Deny)).unwrap();

    let ids = receipts.lock().unwrap();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], "test-receipt-001");
    assert_eq!(ids[1], "test-receipt-001");
}

// --- StderrReceiptSink ---

#[test]
fn stderr_sink_does_not_crash() {
    use hushspec::sink::StderrReceiptSink;

    let sink = StderrReceiptSink;
    let receipt = make_receipt(Decision::Allow);

    // We cannot easily capture stderr in a test, but we can verify it
    // does not panic or return an error.
    let result = sink.send(&receipt);
    assert!(result.is_ok());
}
