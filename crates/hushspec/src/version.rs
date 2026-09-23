//! HushSpec specification version support.
//!
//! Version acceptance follows core spec 2.2: an engine that supports a
//! minor version `X.Y` accepts every `X.Y.Z` document, because patch versions
//! carry only clarifications and errata. This engine implements the 1.0.0
//! semantics, which are identical to 0.2.0, and also accepts 0.1.x and 0.2.x
//! documents (core spec 10).

/// The HushSpec version this engine writes by default.
pub const HUSHSPEC_VERSION: &str = "1.0.0";

/// Minor versions this engine accepts, as `X.Y` strings.
pub const HUSHSPEC_SUPPORTED_MINORS: &[&str] = &["0.1", "0.2", "1.0"];

/// Representative full versions for each supported minor (display only; use
/// [`is_supported`] for acceptance, which accepts every patch level).
pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0", "0.2.0", "1.0.0"];

/// Whether `version` is a well-formed `X.Y.Z` string whose minor version this
/// engine supports. Any patch level of a supported minor is accepted.
#[must_use]
pub fn is_supported(version: &str) -> bool {
    supported_minor(version).is_some()
}

/// The MAJOR component of a well-formed `X.Y.Z` version string, or `None` when
/// the string is not one.
///
/// The document format is versioned by its major component: the 1.0 format
/// differs from 0.x only in the constraints it places on a document (core spec
/// 10), so a constraint introduced with 1.0 is gated on this rather than on the
/// minor an engine happens to support. A major that does not fit an unsigned
/// 32-bit integer names no format any SDK could support, and every SDK
/// applies the same bound.
#[must_use]
pub fn major_version(version: &str) -> Option<u32> {
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
    major.parse().ok()
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
        assert!(is_supported("1.0.0"));
        assert!(is_supported("1.0.3"));
    }

    #[test]
    fn major_version_requires_three_numeric_components() {
        assert_eq!(major_version("1.0.0"), Some(1));
        assert_eq!(major_version("0.2.7"), Some(0));
        assert_eq!(major_version("+1.0.0"), None);
        assert_eq!(major_version("4294967295.0.0"), Some(u32::MAX));
        assert_eq!(major_version("00000000001.0.0"), Some(1));
        assert_eq!(major_version("4294967296.0.0"), None);
        assert_eq!(major_version(&format!("{}.0.0", "9".repeat(5000))), None);
        assert_eq!(major_version("v1.0.0"), None);
        assert_eq!(major_version("1.0"), None);
        assert_eq!(major_version("1.0.0.0"), None);
        assert_eq!(major_version("1.x.0"), None);
        assert_eq!(major_version(""), None);
    }

    #[test]
    fn rejects_unsupported_or_malformed_versions() {
        assert!(!is_supported("0.3.0"));
        assert!(!is_supported("1.7.0"));
        assert!(!is_supported("2.0.0"));
        assert!(!is_supported("0.1"));
        assert!(!is_supported("0.1.0.0"));
        assert!(!is_supported("0.1.x"));
        assert!(!is_supported("+0.1.0"));
        assert!(!is_supported(""));
    }
}
