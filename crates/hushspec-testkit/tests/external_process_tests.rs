#![cfg(target_os = "linux")]

use hushspec_testkit::external::model::ProcessLimits;
use hushspec_testkit::external::process::{ProcessCapture, run_process};
use std::path::Path;
use std::time::{Duration, Instant};

fn shell(script: &str, request: &[u8], limits: &ProcessLimits) -> ProcessCapture {
    let dir = tempfile::tempdir().unwrap();
    run_process(
        Path::new("/bin/sh"),
        &["-c".into(), script.into()],
        request,
        dir.path(),
        limits,
    )
    .unwrap()
}

#[test]
fn external_process_clean_stdin_and_scrubbed_environment() {
    let capture = shell(
        "/bin/cat; printf diagnostic >&2",
        b"{\"request\":true}",
        &ProcessLimits::default(),
    );
    assert_eq!(capture.stdout, b"{\"request\":true}");
    assert_eq!(capture.stderr, b"diagnostic");
    assert_eq!(capture.exit_code, Some(0));
    assert!(capture.failure.is_none());
    let dir = tempfile::tempdir().unwrap();
    let env = run_process(
        Path::new("/usr/bin/env"),
        &[],
        b"",
        dir.path(),
        &ProcessLimits::default(),
    )
    .unwrap();
    let text = String::from_utf8(env.stdout).unwrap();
    let mut lines: Vec<_> = text.lines().collect();
    lines.sort();
    assert_eq!(lines, vec!["LANG=C", "LC_ALL=C", "TZ=UTC"]);
}

#[test]
fn external_process_hang_and_ignored_stdin_are_bounded() {
    let limits = ProcessLimits {
        timeout_ms: 100,
        ..Default::default()
    };
    for request in [vec![], vec![b'x'; 16 * 1024 * 1024]] {
        let before = Instant::now();
        let capture = shell("/bin/sleep 30", &request, &limits);
        assert!(capture.failure.as_deref().unwrap().contains("deadline"));
        assert!(before.elapsed() < Duration::from_secs(3));
    }
}

#[test]
fn external_process_exit_signal_and_floods_are_not_observations() {
    let failure = shell("printf partial; exit 7", b"", &ProcessLimits::default());
    assert_eq!(failure.exit_code, Some(7));
    assert_eq!(failure.stdout, b"partial");
    assert!(failure.failure.is_some());
    let signal = shell("kill -TERM $$", b"", &ProcessLimits::default());
    assert_eq!(signal.signal, Some(15));
    assert!(signal.failure.is_some());
    for script in [
        "while :; do printf abcdefgh; done",
        "while :; do printf abcdefgh >&2; done",
    ] {
        let limits = ProcessLimits {
            stdout_bytes: 1024,
            stderr_bytes: 512,
            ..Default::default()
        };
        let before = Instant::now();
        let capture = shell(script, b"", &limits);
        assert!(capture.failure.is_some());
        assert!(capture.truncated);
        assert!(capture.stdout.len() <= 1024 && capture.stderr.len() <= 512);
        assert!(before.elapsed() < Duration::from_secs(3));
    }
}

#[test]
fn external_process_reaps_group_after_leader_exit_without_pipe_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let before = Instant::now();
    let capture = run_process(
        Path::new("/bin/sh"),
        &[
            "-c".into(),
            "(/bin/sleep 0.4; printf orphan > escaped-marker) & printf done".into(),
        ],
        b"",
        dir.path(),
        &ProcessLimits {
            timeout_ms: 100,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(capture.stdout, b"done");
    assert!(capture.failure.is_none(), "{:?}", capture.failure);
    assert!(before.elapsed() < Duration::from_secs(3));
    std::thread::sleep(Duration::from_millis(500));
    assert!(!dir.path().join("escaped-marker").exists());
}

#[test]
fn external_process_rejects_oversized_request_before_spawn() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        run_process(
            Path::new("/bin/sh"),
            &["-c".into(), "touch should-not-exist".into()],
            &vec![0; 16 * 1024 * 1024 + 1],
            dir.path(),
            &ProcessLimits::default()
        )
        .is_err()
    );
    assert!(!dir.path().join("should-not-exist").exists());
}
