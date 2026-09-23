//! Bounded Linux subprocess lifecycle. This is resource control, not a sandbox.
use super::model::ProcessLimits;
use std::path::Path;

#[derive(Debug)]
pub struct ProcessCapture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub failure: Option<String>,
    pub elapsed_ms: u64,
    pub truncated: bool,
}

#[cfg(not(target_os = "linux"))]
pub fn run_process(
    _executable: &Path,
    _args: &[String],
    _request: &[u8],
    _cwd: &Path,
    _limits: &ProcessLimits,
) -> Result<ProcessCapture, String> {
    Err("external process execution currently requires Linux".into())
}

#[cfg(target_os = "linux")]
pub use linux::run_process;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct Guard {
        child: Child,
        reaped: bool,
    }
    impl Guard {
        fn kill_group(&mut self) {
            if !self.reaped {
                // SAFETY: child owns this process-group ID until it is reaped.
                // waitid(WNOWAIT) below deliberately retains that ownership.
                unsafe {
                    libc::kill(-(self.child.id() as i32), libc::SIGKILL);
                }
                let _ = self.child.kill();
            }
        }
        fn exited(&self) -> Result<bool, String> {
            // SAFETY: zeroed siginfo is valid output storage for waitid.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: direct child ID and valid output pointer; WNOWAIT does not reap.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id(),
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    return Ok(false);
                }
                return Err(error.to_string());
            }
            // SAFETY: successful waitid populated the SIGCHLD union variant.
            Ok(unsafe { info.si_pid() } != 0)
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if !self.reaped {
                self.kill_group();
                let _ = self.child.wait();
            }
        }
    }

    fn nonblocking(fd: &impl AsRawFd) -> Result<(), String> {
        // SAFETY: fd is a live owned pipe; fcntl neither consumes nor aliases it.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: valid flags read above; O_NONBLOCK applies to this pipe description.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }

    enum ReadState {
        Open,
        Eof,
        Overflow,
    }
    fn drain(
        pipe: &mut impl Read,
        output: &mut Vec<u8>,
        limit: usize,
    ) -> Result<ReadState, String> {
        // One bounded read per stream per iteration also bounds deadline latency
        // when a child continuously refills the pipe faster than we can drain it.
        let mut buffer = [0u8; 8192];
        match pipe.read(&mut buffer) {
            Ok(0) => Ok(ReadState::Eof),
            Ok(n) => {
                let remaining = limit.saturating_sub(output.len());
                output.extend_from_slice(&buffer[..n.min(remaining)]);
                Ok(if n > remaining {
                    ReadState::Overflow
                } else {
                    ReadState::Open
                })
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(ReadState::Open)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn run_process(
        executable: &Path,
        args: &[String],
        request: &[u8],
        cwd: &Path,
        limits: &ProcessLimits,
    ) -> Result<ProcessCapture, String> {
        limits.validate()?;
        if request.len() > super::super::model::MAX_REQUEST {
            return Err("request exceeds 16 MiB".into());
        }
        let started = Instant::now();
        let deadline = started + Duration::from_millis(limits.timeout_ms);
        let mut input = tempfile::tempfile_in(cwd).map_err(|e| e.to_string())?;
        input.write_all(request).map_err(|e| e.to_string())?;
        input.rewind().map_err(|e| e.to_string())?;
        let child = Command::new(executable)
            .args(args)
            .current_dir(cwd)
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("TZ", "UTC")
            .stdin(Stdio::from(input))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| format!("engine spawn failed: {e}"))?;
        let mut guard = Guard {
            child,
            reaped: false,
        };
        let mut stdout = guard.child.stdout.take().ok_or("missing stdout pipe")?;
        let mut stderr = guard.child.stderr.take().ok_or("missing stderr pipe")?;
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let mut capture = ProcessCapture {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            signal: None,
            failure: None,
            elapsed_ms: 0,
            truncated: false,
        };
        let (mut out_eof, mut err_eof, mut leader_exited) = (false, false, false);
        loop {
            if Instant::now() >= deadline {
                capture.failure = Some("engine deadline exceeded".into());
                break;
            }
            for (pipe, output, eof, limit) in [
                (
                    &mut stdout as &mut dyn Read,
                    &mut capture.stdout,
                    &mut out_eof,
                    limits.stdout_bytes,
                ),
                (
                    &mut stderr as &mut dyn Read,
                    &mut capture.stderr,
                    &mut err_eof,
                    limits.stderr_bytes,
                ),
            ] {
                if *eof {
                    continue;
                }
                match drain(&mut { pipe }, output, limit) {
                    Ok(ReadState::Eof) => *eof = true,
                    Ok(ReadState::Overflow) => {
                        capture.truncated = true;
                        capture.failure = Some("engine output limit exceeded".into());
                    }
                    Ok(ReadState::Open) => {}
                    Err(e) => {
                        capture.failure = Some(format!("engine output read failed: {e}"));
                    }
                }
            }
            if capture.stdout.len() + capture.stderr.len() > limits.total_output_bytes {
                let remaining = limits
                    .total_output_bytes
                    .saturating_sub(capture.stdout.len());
                capture.stdout.truncate(limits.total_output_bytes);
                capture.stderr.truncate(remaining);
                capture.truncated = true;
                capture.failure = Some("engine aggregate output limit exceeded".into());
            }
            if capture.failure.is_some() {
                break;
            }
            if !leader_exited && guard.exited()? {
                leader_exited = true;
                guard.kill_group();
            }
            if leader_exited && out_eof && err_eof {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        guard.kill_group();
        let status = guard.child.wait().map_err(|e| e.to_string())?;
        guard.reaped = true;
        capture.exit_code = status.code();
        capture.signal = status.signal();
        if !status.success() && capture.failure.is_none() {
            capture.failure = Some(format!("engine exited unsuccessfully: {status}"));
        }
        capture.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(capture)
    }
}
