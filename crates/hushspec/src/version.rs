//! HushSpec specification version support.
//!
//! Version acceptance follows core spec 2.2: an engine that supports a
//! minor version `X.Y` accepts every `X.Y.Z` document, because patch versions
//! carry only clarifications and errata. This engine implements the 0.2.0
//! semantics and also accepts 0.1.x documents (evaluated under 0.2 semantics).

/// The HushSpec version this engine writes by default.
pub const HUSHSPEC_VERSION: &str = "0.2.0";

/// Minor versions this engine accepts, as `X.Y` strings.
pub const HUSHSPEC_SUPPORTED_MINORS: &[&str] = &["0.1", "0.2"];

/// Representative full versions for each supported minor (display only; use
/// [`is_supported`] for acceptance, which accepts every patch level).
pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0", "0.2.0"];

/// Whether `version` is a well-formed `0.Y.Z` string whose minor version this
/// engine supports. Any patch level of a supported minor is accepted.
#[must_use]
pub fn is_supported(version: &str) -> bool {
    supported_minor(version).is_some()
}

/// The `X.Y` minor of a well-formed, supported version string.
#[must_use]
pub fn supported_minor(version: &str) -> Option<&'static str> {
    let mut parts = version.split('.');
    let major = parts.next()?;
    let minor = parts.next()?;
    let patch = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let is_digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    if !is_digits(major) || !is_digits(minor) || !is_digits(patch) {
        return None;
    }
    HUSHSPEC_SUPPORTED_MINORS
        .iter()
        .copied()
        .find(|supported| supported.split_once('.') == Some((major, minor)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_every_patch_of_a_supported_minor() {
        assert!(is_supported("0.1.0"));
        assert!(is_supported("0.1.1"));
        assert!(is_supported("0.1.99"));
        assert!(is_supported("0.2.0"));
        assert!(is_supported("0.2.7"));
    }

    #[test]
    fn rejects_unsupported_or_malformed_versions() {
        assert!(!is_supported("0.3.0"));
        assert!(!is_supported("1.0.0"));
        assert!(!is_supported("0.1"));
        assert!(!is_supported("0.1.0.0"));
        assert!(!is_supported("0.1.x"));
        assert!(!is_supported("+0.1.0"));
        assert!(!is_supported(""));
    }
}
