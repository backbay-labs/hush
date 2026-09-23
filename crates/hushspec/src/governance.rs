//! Governance metadata validation for HushSpec policies.
//!
//! Governance metadata is **advisory only** -- it has no impact on evaluation.
//! Most checks here emit warnings that support enterprise policy lifecycle
//! workflows (`h2h audit`, and `h2h audit --strict` where every warning is
//! fatal). A small number describe a document that contradicts itself -- a
//! policy that supersedes its own version -- and are reported as errors, so
//! `validate` rejects the document outright.

use crate::schema::HushSpec;

pub use crate::generated_models::{
    ChangelogEntry, Classification, ControlMapping, GovernanceMetadata, LifecycleState,
};

/// How seriously a consumer should take a governance finding.
///
/// `h2h audit --strict` promotes every `Warning` to a non-zero exit; an
/// `Error` is a validation error in its own right and makes the document
/// invalid everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceSeverity {
    Warning,
    Error,
}

impl GovernanceSeverity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// One governance check outcome: a stable `code`, the document `path` it is
/// about, and a human-readable `message`.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernanceFinding {
    pub code: String,
    pub severity: GovernanceSeverity,
    /// Dot path into the document the finding concerns, e.g.
    /// `metadata.approved_by`.
    pub path: String,
    pub message: String,
}

/// Historical name for [`GovernanceFinding`], kept so callers that only read
/// `code`/`message` keep compiling.
#[deprecated(
    note = "use `GovernanceFinding`: a finding carries a severity and is not always a warning"
)]
pub type GovernanceWarning = GovernanceFinding;

fn warn(code: &str, path: &str, message: String) -> GovernanceFinding {
    GovernanceFinding {
        code: code.into(),
        severity: GovernanceSeverity::Warning,
        path: path.into(),
        message,
    }
}

fn err(code: &str, path: &str, message: String) -> GovernanceFinding {
    GovernanceFinding {
        code: code.into(),
        severity: GovernanceSeverity::Error,
        path: path.into(),
        message,
    }
}

/// Governance metadata checks.
///
/// Every finding except `GOV_SELF_SUPERSEDES` is advisory; callers decide
/// whether warnings are fatal (`h2h audit --strict`).
#[must_use]
pub fn validate_governance(spec: &HushSpec) -> Vec<GovernanceFinding> {
    let mut findings = Vec::new();

    let Some(metadata) = &spec.metadata else {
        return findings;
    };

    let today = current_date_iso();

    if let Some(state) = &metadata.lifecycle_state
        && matches!(state, LifecycleState::Deprecated | LifecycleState::Archived)
    {
        findings.push(warn(
            "GOV_LIFECYCLE",
            "metadata.lifecycle_state",
            format!("policy lifecycle state is '{}'", lifecycle_str(state)),
        ));
    }

    if let Some(expiry) = &metadata.expiry_date
        && is_past_date(expiry, &today)
    {
        findings.push(warn(
            "GOV_EXPIRED",
            "metadata.expiry_date",
            format!("policy expiry_date '{expiry}' is in the past"),
        ));
    }

    if metadata.approved_by.is_some() && metadata.approval_date.is_none() {
        findings.push(warn(
            "GOV_MISSING_APPROVAL_DATE",
            "metadata.approval_date",
            "approved_by is set but approval_date is missing".into(),
        ));
    }

    if let Some(Classification::Restricted) = &metadata.classification
        && metadata.approved_by.is_none()
    {
        findings.push(warn(
            "GOV_RESTRICTED_NO_APPROVER",
            "metadata.approved_by",
            "classification is 'restricted' but no approved_by is set".into(),
        ));
    }

    // Separation of duties: whoever wrote the revision must not also be the one
    // who signed it off. Compared trimmed and case-insensitively, because
    // "Sec@example.com " and "sec@example.com" are the same person, and a
    // check that a copy-paste with different capitalization defeats is no
    // check at all.
    if let (Some(author), Some(approver)) = (&metadata.author, &metadata.approved_by)
        && same_identity(author, approver)
    {
        findings.push(warn(
            "GOV_SOD_VIOLATION",
            "metadata.approved_by",
            format!(
                "author and approved_by are the same identity '{}': separation of duties requires a different approver",
                author.trim()
            ),
        ));
    }

    if let Some(state) = &metadata.lifecycle_state
        && matches!(state, LifecycleState::Approved | LifecycleState::Deployed)
        && metadata.approved_by.is_none()
    {
        findings.push(warn(
            "GOV_UNAPPROVED_STATE",
            "metadata.approved_by",
            format!(
                "lifecycle_state is '{}' but no approved_by is set",
                lifecycle_str(state)
            ),
        ));
    }

    if let Some(next_review) = &metadata.next_review_date
        && is_past_date(next_review, &today)
    {
        findings.push(warn(
            "GOV_REVIEW_OVERDUE",
            "metadata.next_review_date",
            format!("policy next_review_date '{next_review}' is in the past"),
        ));
    }

    if let (Some(supersedes), Some(policy_version)) =
        (&metadata.supersedes, metadata.policy_version)
        && supersedes.trim() == policy_version.to_string()
    {
        findings.push(err(
            "GOV_SELF_SUPERSEDES",
            "metadata.supersedes",
            format!("metadata.supersedes '{supersedes}' is the policy's own policy_version"),
        ));
    }

    if let Some(index) = changelog_disorder(&metadata.changelog) {
        findings.push(warn(
            "GOV_CHANGELOG_ORDER",
            "metadata.changelog",
            format!("changelog entries are not in descending version/date order at entry {index}"),
        ));
    }

    findings
}

fn lifecycle_str(state: &LifecycleState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{state:?}"))
}

/// Two identities are the same once surrounding whitespace and ASCII case are
/// normalized away. An empty identity never matches: a blank `author` is not a
/// separation-of-duties violation.
fn same_identity(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    !left.is_empty() && left.eq_ignore_ascii_case(right)
}

/// `date` is strictly before `today`. A value that is not a real calendar date
/// is never "in the past": `validate` already rejects it with `InvalidDate`,
/// and guessing at its meaning here would report the same problem twice.
fn is_past_date(date: &str, today: &str) -> bool {
    parse_iso_date(date).is_some() && date < today
}

/// Index of the first changelog entry that is not ordered after the one above
/// it (the list runs newest first), or `None` when the list is ordered.
fn changelog_disorder(entries: &[ChangelogEntry]) -> Option<usize> {
    for index in 1..entries.len() {
        let previous = &entries[index - 1];
        let current = &entries[index];
        let ordered = match compare_versions(&previous.version, &current.version) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => previous.date >= current.date,
        };
        if !ordered {
            return Some(index);
        }
    }
    None
}

/// Numeric comparison when both versions are plain integers (the shape
/// `metadata.policy_version` takes), lexicographic otherwise.
fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.trim().parse::<u64>(), right.trim().parse::<u64>()) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => left.cmp(right),
    }
}

/// Parse `YYYY-MM-DD` into `(year, month, day)`, rejecting anything that is not
/// a real calendar date -- including Feb 29 outside a leap year, and any form
/// other than exactly four-two-two zero-padded digits.
#[must_use]
pub fn parse_iso_date(value: &str) -> Option<(u32, u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if !bytes
        .iter()
        .enumerate()
        .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
    {
        return None;
    }

    let year: u32 = value[0..4].parse().ok()?;
    let month: u32 = value[5..7].parse().ok()?;
    let day: u32 = value[8..10].parse().ok()?;

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    Some((year, month, day))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Today in UTC, as the `YYYY-MM-DD` the date fields are compared against.
fn current_date_iso() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated_models::{Classification, GovernanceMetadata, LifecycleState};

    fn minimal_spec() -> HushSpec {
        HushSpec {
            hushspec: "0.1.0".into(),
            name: None,
            description: None,
            extends: None,
            merge_strategy: None,
            rules: None,
            extensions: None,
            metadata: None,
        }
    }

    fn empty_metadata() -> GovernanceMetadata {
        GovernanceMetadata {
            author: None,
            approved_by: None,
            approval_date: None,
            classification: None,
            change_ticket: None,
            lifecycle_state: None,
            policy_version: None,
            effective_date: None,
            expiry_date: None,
            owner: None,
            reviewers: Vec::new(),
            next_review_date: None,
            changelog: Vec::new(),
            supersedes: None,
            controls: Vec::new(),
        }
    }

    fn entry(version: &str, date: &str) -> ChangelogEntry {
        ChangelogEntry {
            version: version.into(),
            date: date.into(),
            author: None,
            summary: "change".into(),
        }
    }

    fn findings_for(metadata: GovernanceMetadata) -> Vec<GovernanceFinding> {
        let mut spec = minimal_spec();
        spec.metadata = Some(metadata);
        validate_governance(&spec)
    }

    fn codes(findings: &[GovernanceFinding]) -> Vec<&str> {
        findings.iter().map(|f| f.code.as_str()).collect()
    }

    #[test]
    fn no_metadata_no_warnings() {
        let spec = minimal_spec();
        assert!(validate_governance(&spec).is_empty());
    }

    #[test]
    fn empty_metadata_no_warnings() {
        assert!(findings_for(empty_metadata()).is_empty());
    }

    #[test]
    fn deprecated_lifecycle_warns() {
        let mut metadata = empty_metadata();
        metadata.lifecycle_state = Some(LifecycleState::Deprecated);
        assert_eq!(codes(&findings_for(metadata)), ["GOV_LIFECYCLE"]);
    }

    #[test]
    fn archived_lifecycle_warns() {
        let mut metadata = empty_metadata();
        metadata.lifecycle_state = Some(LifecycleState::Archived);
        assert_eq!(codes(&findings_for(metadata)), ["GOV_LIFECYCLE"]);
    }

    #[test]
    fn deployed_with_approver_no_warning() {
        let mut metadata = empty_metadata();
        metadata.lifecycle_state = Some(LifecycleState::Deployed);
        metadata.approved_by = Some("ciso@company.com".into());
        metadata.approval_date = Some("2024-03-15".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn expired_policy_warns() {
        let mut metadata = empty_metadata();
        metadata.expiry_date = Some("2020-01-01".into());
        let findings = findings_for(metadata);
        assert_eq!(codes(&findings), ["GOV_EXPIRED"]);
        assert_eq!(findings[0].severity, GovernanceSeverity::Warning);
        assert_eq!(findings[0].path, "metadata.expiry_date");
    }

    #[test]
    fn future_expiry_no_warning() {
        let mut metadata = empty_metadata();
        metadata.expiry_date = Some("2099-12-31".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn approved_by_without_date_warns() {
        let mut metadata = empty_metadata();
        metadata.approved_by = Some("ciso@company.com".into());
        assert_eq!(
            codes(&findings_for(metadata)),
            ["GOV_MISSING_APPROVAL_DATE"]
        );
    }

    #[test]
    fn approved_by_with_date_no_warning() {
        let mut metadata = empty_metadata();
        metadata.approved_by = Some("ciso@company.com".into());
        metadata.approval_date = Some("2024-03-15".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn restricted_without_approver_warns() {
        let mut metadata = empty_metadata();
        metadata.classification = Some(Classification::Restricted);
        assert_eq!(
            codes(&findings_for(metadata)),
            ["GOV_RESTRICTED_NO_APPROVER"]
        );
    }

    #[test]
    fn restricted_with_approver_no_warning() {
        let mut metadata = empty_metadata();
        metadata.classification = Some(Classification::Restricted);
        metadata.approved_by = Some("ciso@company.com".into());
        metadata.approval_date = Some("2024-03-15".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn author_equal_to_approver_is_a_sod_violation() {
        let mut metadata = empty_metadata();
        metadata.author = Some("security@company.com".into());
        metadata.approved_by = Some("security@company.com".into());
        metadata.approval_date = Some("2024-03-15".into());
        let findings = findings_for(metadata);
        assert_eq!(codes(&findings), ["GOV_SOD_VIOLATION"]);
        assert_eq!(findings[0].severity, GovernanceSeverity::Warning);
        assert_eq!(findings[0].path, "metadata.approved_by");
    }

    #[test]
    fn sod_check_ignores_case_and_surrounding_whitespace() {
        let mut metadata = empty_metadata();
        metadata.author = Some("  Security@Company.com ".into());
        metadata.approved_by = Some("security@company.com".into());
        metadata.approval_date = Some("2024-03-15".into());
        assert_eq!(codes(&findings_for(metadata)), ["GOV_SOD_VIOLATION"]);
    }

    #[test]
    fn distinct_author_and_approver_no_warning() {
        let mut metadata = empty_metadata();
        metadata.author = Some("security@company.com".into());
        metadata.approved_by = Some("ciso@company.com".into());
        metadata.approval_date = Some("2024-03-15".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn approved_state_without_approver_warns() {
        let mut metadata = empty_metadata();
        metadata.lifecycle_state = Some(LifecycleState::Approved);
        assert_eq!(codes(&findings_for(metadata)), ["GOV_UNAPPROVED_STATE"]);
    }

    #[test]
    fn deployed_state_without_approver_warns() {
        let mut metadata = empty_metadata();
        metadata.lifecycle_state = Some(LifecycleState::Deployed);
        assert_eq!(codes(&findings_for(metadata)), ["GOV_UNAPPROVED_STATE"]);
    }

    #[test]
    fn draft_without_approver_no_warning() {
        let mut metadata = empty_metadata();
        metadata.lifecycle_state = Some(LifecycleState::Draft);
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn overdue_review_warns() {
        let mut metadata = empty_metadata();
        metadata.next_review_date = Some("2020-06-01".into());
        let findings = findings_for(metadata);
        assert_eq!(codes(&findings), ["GOV_REVIEW_OVERDUE"]);
        assert_eq!(findings[0].path, "metadata.next_review_date");
    }

    #[test]
    fn future_review_no_warning() {
        let mut metadata = empty_metadata();
        metadata.next_review_date = Some("2099-06-01".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn malformed_expiry_is_not_reported_as_past() {
        // The format error is `validate`'s job (E011); reporting it here too
        // would double-count one problem.
        let mut metadata = empty_metadata();
        metadata.expiry_date = Some("01/02/2020".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn superseding_own_version_is_an_error() {
        let mut metadata = empty_metadata();
        metadata.policy_version = Some(4);
        metadata.supersedes = Some("4".into());
        let findings = findings_for(metadata);
        assert_eq!(codes(&findings), ["GOV_SELF_SUPERSEDES"]);
        assert_eq!(findings[0].severity, GovernanceSeverity::Error);
        assert_eq!(findings[0].path, "metadata.supersedes");
    }

    #[test]
    fn superseding_the_previous_version_is_fine() {
        let mut metadata = empty_metadata();
        metadata.policy_version = Some(4);
        metadata.supersedes = Some("3".into());
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn descending_changelog_no_warning() {
        let mut metadata = empty_metadata();
        metadata.changelog = vec![
            entry("3", "2025-03-01"),
            entry("2", "2024-07-01"),
            entry("1", "2024-01-01"),
        ];
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn ascending_changelog_warns() {
        let mut metadata = empty_metadata();
        metadata.changelog = vec![entry("1", "2024-01-01"), entry("2", "2024-07-01")];
        let findings = findings_for(metadata);
        assert_eq!(codes(&findings), ["GOV_CHANGELOG_ORDER"]);
        assert_eq!(findings[0].path, "metadata.changelog");
    }

    #[test]
    fn equal_versions_fall_back_to_date_order() {
        let mut metadata = empty_metadata();
        metadata.changelog = vec![entry("2", "2024-01-01"), entry("2", "2024-07-01")];
        assert_eq!(codes(&findings_for(metadata)), ["GOV_CHANGELOG_ORDER"]);
    }

    #[test]
    fn single_changelog_entry_no_warning() {
        let mut metadata = empty_metadata();
        metadata.changelog = vec![entry("1", "2024-01-01")];
        assert!(findings_for(metadata).is_empty());
    }

    #[test]
    fn parse_iso_date_accepts_real_dates() {
        assert_eq!(parse_iso_date("2024-02-29"), Some((2024, 2, 29)));
        assert_eq!(parse_iso_date("2000-02-29"), Some((2000, 2, 29)));
        assert_eq!(parse_iso_date("1970-01-01"), Some((1970, 1, 1)));
        assert_eq!(parse_iso_date("2024-12-31"), Some((2024, 12, 31)));
    }

    #[test]
    fn parse_iso_date_rejects_impossible_dates() {
        for value in [
            "2023-02-29",
            "1900-02-29",
            "2024-13-01",
            "2024-00-10",
            "2024-04-31",
            "2024-01-00",
            "2024-1-01",
            "24-01-01",
            "2024/01/01",
            "2024-01-01T00:00:00Z",
            "",
            "not-a-date",
        ] {
            assert_eq!(parse_iso_date(value), None, "{value} should be rejected");
        }
    }

    #[test]
    fn parse_with_metadata() {
        let yaml = r#"
hushspec: "0.1.0"
name: "test-policy"
metadata:
  author: "security-team@company.com"
  approved_by: "ciso@company.com"
  approval_date: "2024-03-15"
  classification: internal
  lifecycle_state: deployed
  policy_version: 3
  change_ticket: "SEC-1234"
  effective_date: "2024-03-15"
  expiry_date: "2025-03-15"
  owner: "platform-security@company.com"
  reviewers:
    - "appsec@company.com"
  next_review_date: "2025-01-15"
  supersedes: "2"
  changelog:
    - version: "3"
      date: "2024-03-15"
      author: "security-team@company.com"
      summary: "Tighten egress allowlist"
"#;
        let spec = HushSpec::parse(yaml).expect("should parse");
        assert_eq!(spec.name.as_deref(), Some("test-policy"));
        let m = spec.metadata.as_ref().unwrap();
        assert_eq!(m.author.as_deref(), Some("security-team@company.com"));
        assert_eq!(m.approved_by.as_deref(), Some("ciso@company.com"));
        assert_eq!(m.approval_date.as_deref(), Some("2024-03-15"));
        assert_eq!(m.classification, Some(Classification::Internal));
        assert_eq!(m.lifecycle_state, Some(LifecycleState::Deployed));
        assert_eq!(m.policy_version, Some(3));
        assert_eq!(m.change_ticket.as_deref(), Some("SEC-1234"));
        assert_eq!(m.effective_date.as_deref(), Some("2024-03-15"));
        assert_eq!(m.expiry_date.as_deref(), Some("2025-03-15"));
        assert_eq!(m.owner.as_deref(), Some("platform-security@company.com"));
        assert_eq!(m.reviewers, vec!["appsec@company.com".to_string()]);
        assert_eq!(m.next_review_date.as_deref(), Some("2025-01-15"));
        assert_eq!(m.supersedes.as_deref(), Some("2"));
        assert_eq!(m.changelog.len(), 1);
        assert_eq!(m.changelog[0].version, "3");
        assert_eq!(m.changelog[0].summary, "Tighten egress allowlist");
    }

    #[test]
    fn changelog_entry_rejects_unknown_keys() {
        let yaml = r#"
hushspec: "0.1.0"
metadata:
  changelog:
    - version: "1"
      date: "2024-01-01"
      summary: "initial"
      reason: "not a field"
"#;
        assert!(HushSpec::parse(yaml).is_err());
    }

    #[test]
    fn parse_without_metadata_backward_compatible() {
        let yaml = r#"
hushspec: "0.1.0"
name: "simple-policy"
rules:
  egress:
    enabled: true
    allow: ["*.example.com"]
"#;
        let spec = HushSpec::parse(yaml).expect("should parse without metadata");
        assert!(spec.metadata.is_none());
    }

    #[test]
    fn classification_enum_roundtrip() {
        for value in &["public", "internal", "confidential", "restricted"] {
            let yaml = format!(
                r#"
hushspec: "0.1.0"
metadata:
  classification: {value}
"#
            );
            let spec = HushSpec::parse(&yaml).expect("should parse");
            let m = spec.metadata.unwrap();
            assert!(m.classification.is_some());
        }
    }

    #[test]
    fn lifecycle_state_enum_roundtrip() {
        for value in &[
            "draft",
            "review",
            "approved",
            "deployed",
            "deprecated",
            "archived",
        ] {
            let yaml = format!(
                r#"
hushspec: "0.1.0"
metadata:
  lifecycle_state: {value}
"#
            );
            let spec = HushSpec::parse(&yaml).expect("should parse");
            let m = spec.metadata.unwrap();
            assert!(m.lifecycle_state.is_some());
        }
    }

    #[test]
    fn current_date_iso_is_a_calendar_date() {
        let today = current_date_iso();
        assert_eq!(today.len(), 10, "{today}");
        assert!(
            chrono::NaiveDate::parse_from_str(&today, "%Y-%m-%d").is_ok(),
            "{today} must be the YYYY-MM-DD the metadata dates are compared against"
        );
    }
}
