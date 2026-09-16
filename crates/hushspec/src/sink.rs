use crate::evaluate::Decision;
use crate::receipt::DecisionReceipt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A hash-linked log could not be continued or written consistently.
    #[error("log chain error: {0}")]
    Chain(String),
}

/// Where an engine puts the receipts it records.
///
/// A sink must never break enforcement: implementations report a failure as
/// [`SinkError`] rather than panicking, and callers surface it on the
/// `sink.error` observer channel instead of denying on it.
pub trait ReceiptSink: Send + Sync {
    /// Record one decision receipt.
    ///
    /// # Errors
    ///
    /// Whatever the destination reports; see [`SinkError`].
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError>;

    /// Record a policy-in-effect event (log spec 6). Sinks that only carry
    /// receipts ignore it; the hash-linked log writes it as an entry.
    fn record_policy_event(&self, _event: &crate::log::PolicyEvent) -> Result<(), SinkError> {
        Ok(())
    }

    /// How a `sink.error` observer event names this sink in its `source`.
    ///
    /// Defaults to the implementing type's own name; override it with
    /// something an operator can place, such as a path or an endpoint.
    fn name(&self) -> &'static str {
        short_type_name(std::any::type_name::<Self>())
    }
}

/// The last segment of a fully qualified type path, with any generic
/// arguments left off: `hushspec::sink::FilteredSink` is `FilteredSink`.
fn short_type_name(path: &'static str) -> &'static str {
    let bare = path.split('<').next().unwrap_or(path);
    bare.rsplit("::").next().unwrap_or(bare)
}

/// Appends receipts as JSON Lines to a file.
pub struct FileReceiptSink {
    path: PathBuf,
}

impl FileReceiptSink {
    /// Append receipts to `path`, creating it on the first write.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl ReceiptSink for FileReceiptSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let mut record = serde_json::to_string(receipt)?;
        record.push('\n');
        file.write_all(record.as_bytes())?;
        Ok(())
    }
}

/// Pretty-prints receipts to stderr, prefixed with `[hushspec]`.
pub struct StderrReceiptSink;

impl ReceiptSink for StderrReceiptSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        let json = serde_json::to_string_pretty(receipt)?;
        eprintln!("[hushspec] {}", json);
        Ok(())
    }
}

/// Only forwards receipts matching configured decisions.
pub struct FilteredSink {
    inner: Box<dyn ReceiptSink>,
    decisions: Vec<Decision>,
}

impl FilteredSink {
    /// Forward only the receipts whose decision is in `decisions`.
    #[must_use]
    pub fn new(sink: Box<dyn ReceiptSink>, decisions: Vec<Decision>) -> Self {
        Self {
            inner: sink,
            decisions,
        }
    }

    /// Forward only denials.
    #[must_use]
    pub fn deny_only(sink: Box<dyn ReceiptSink>) -> Self {
        Self::new(sink, vec![Decision::Deny])
    }
}

impl ReceiptSink for FilteredSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        if self.decisions.contains(&receipt.decision) {
            self.inner.send(receipt)
        } else {
            Ok(())
        }
    }
}

/// Fans out to multiple sinks. Returns the first error but invokes all sinks.
pub struct MultiSink {
    sinks: Vec<Box<dyn ReceiptSink>>,
}

impl MultiSink {
    /// Fan every receipt out to all of `sinks`.
    #[must_use]
    pub fn new(sinks: Vec<Box<dyn ReceiptSink>>) -> Self {
        Self { sinks }
    }
}

impl ReceiptSink for MultiSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        let mut first_error: Option<SinkError> = None;
        for sink in &self.sinks {
            if let Err(e) = sink.send(receipt)
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn record_policy_event(&self, event: &crate::log::PolicyEvent) -> Result<(), SinkError> {
        let mut first_error: Option<SinkError> = None;
        for sink in &self.sinks {
            if let Err(e) = sink.record_policy_event(event)
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// No-op sink. `send()` always succeeds.
pub struct NullSink;

impl ReceiptSink for NullSink {
    fn send(&self, _receipt: &DecisionReceipt) -> Result<(), SinkError> {
        Ok(())
    }
}

type SinkCallback = dyn Fn(&DecisionReceipt) -> Result<(), SinkError> + Send + Sync;

/// Invokes a closure for each receipt.
pub struct CallbackSink {
    callback: Box<SinkCallback>,
}

impl CallbackSink {
    /// Hand each receipt to `callback`.
    #[must_use]
    pub fn new(
        callback: impl Fn(&DecisionReceipt) -> Result<(), SinkError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl ReceiptSink for CallbackSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        (self.callback)(receipt)
    }
}
