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
    /// A sink behind a [`MultiSink`] refused what it was handed, named so an
    /// operator can tell which destination stopped taking evidence.
    #[error("sink {sink}: {source}")]
    Fanout {
        /// The sink that refused, by [`ReceiptSink::name`].
        sink: &'static str,
        /// What it reported.
        #[source]
        source: Box<SinkError>,
    },
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
    /// Defaults to the implementing type's own name, which is what the other
    /// SDKs report; a sink with a more telling constant name overrides it.
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

/// Fans out to several sinks.
///
/// Every sink is attempted whatever the ones before it did -- one destination
/// refusing a receipt must not cost the others theirs -- and the first failure
/// is reported as a [`SinkError::Fanout`] naming the sink that refused, so a
/// guard raises a `sink.error` observer event for it.
pub struct MultiSink {
    sinks: Vec<Box<dyn ReceiptSink>>,
}

impl MultiSink {
    /// Fan every receipt out to all of `sinks`.
    #[must_use]
    pub fn new(sinks: Vec<Box<dyn ReceiptSink>>) -> Self {
        Self { sinks }
    }

    fn fan_out(
        &self,
        deliver: impl Fn(&dyn ReceiptSink) -> Result<(), SinkError>,
    ) -> Result<(), SinkError> {
        let mut first_error: Option<SinkError> = None;
        for sink in &self.sinks {
            if let Err(error) = deliver(sink.as_ref())
                && first_error.is_none()
            {
                first_error = Some(SinkError::Fanout {
                    sink: sink.name(),
                    source: Box::new(error),
                });
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl ReceiptSink for MultiSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        self.fan_out(|sink| sink.send(receipt))
    }

    fn record_policy_event(&self, event: &crate::log::PolicyEvent) -> Result<(), SinkError> {
        self.fan_out(|sink| sink.record_policy_event(event))
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
