//! Conditional rules system for HushSpec.
//!
//! Provides a `Condition` type that can be attached to rule blocks via the
//! `when` field. Conditions evaluate against a `RuntimeContext` to determine
//! whether a rule block is active.
//!
//! Design principles:
//! - **Fail-closed**: missing context fields cause conditions to evaluate to `false`.
//! - **Deterministic**: same context + condition = same result, always.
//! - **Not Turing-complete**: fixed predicate types composed with AND/OR/NOT.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum allowed nesting depth for compound conditions.
const MAX_NESTING_DEPTH: usize = 8;

/// A condition that gates whether a rule block is active.
///
/// Conditions are evaluated before rule-block-specific logic. When a condition
/// evaluates to `false`, the rule block is treated as inert (as if `enabled: false`).
///
/// Multiple fields on a single `Condition` are combined with AND semantics:
/// all present fields must evaluate to `true`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// Time window during which the rule block is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindowCondition>,

    /// Context key-value pairs that must match the runtime context.
    /// All entries must match (AND semantics across keys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<HashMap<String, serde_json::Value>>,

    /// All sub-conditions must be true (AND).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all_of: Option<Vec<Condition>>,

    /// At least one sub-condition must be true (OR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any_of: Option<Vec<Condition>>,

    /// The sub-condition must be false (NOT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not: Option<Box<Condition>>,
}

/// Time window condition: activates a rule block during specific time periods.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindowCondition {
    /// Start time in `HH:MM` (24-hour) format.
    pub start: String,
    /// End time in `HH:MM` (24-hour) format.
    pub end: String,
    /// IANA timezone identifier. Defaults to `"UTC"` when not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Day abbreviations: `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`.
    /// Defaults to all days when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub days: Vec<String>,
}

/// Runtime context provided by the enforcement engine at evaluation time.
///
/// Conditions reference context fields using dot-delimited paths (e.g.,
/// `user.role`, `environment`). The engine populates this struct from its
/// runtime environment.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RuntimeContext {
    /// User attributes (id, role, tier, groups, department, etc.).
    #[serde(default)]
    pub user: HashMap<String, serde_json::Value>,

    /// Deployment environment label (e.g., `"production"`, `"staging"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,

    /// Deployment metadata (region, cluster, cloud_provider).
    #[serde(default)]
    pub deployment: HashMap<String, serde_json::Value>,

    /// Agent metadata (id, type, model, capabilities, version).
    #[serde(default)]
    pub agent: HashMap<String, serde_json::Value>,

    /// Session metadata (id, started_at, action_count, duration_seconds).
    #[serde(default)]
    pub session: HashMap<String, serde_json::Value>,

    /// Request metadata (id, timestamp).
    #[serde(default)]
    pub request: HashMap<String, serde_json::Value>,

    /// Engine-specific custom fields.
    #[serde(default)]
    pub custom: HashMap<String, serde_json::Value>,

    /// Current time override for testing (ISO 8601).
    /// If `None`, the system clock is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_time: Option<String>,
}

/// Missing context fields cause the condition to evaluate to false (fail-closed).
pub fn evaluate_condition(condition: &Condition, context: &RuntimeContext) -> bool {
    evaluate_condition_depth(condition, context, 0)
}

fn evaluate_condition_depth(condition: &Condition, context: &RuntimeContext, depth: usize) -> bool {
    if depth > MAX_NESTING_DEPTH {
        // Exceeded maximum nesting depth -- fail-closed.
        return false;
    }

    if let Some(tw) = &condition.time_window
        && !check_time_window(tw, context)
    {
        return false;
    }

    if let Some(ctx) = &condition.context
        && !check_context_match(ctx, context)
    {
        return false;
    }

    if let Some(all) = &condition.all_of
        && !all
            .iter()
            .all(|c| evaluate_condition_depth(c, context, depth + 1))
    {
        return false;
    }

    if let Some(any) = &condition.any_of
        && !any
            .iter()
            .any(|c| evaluate_condition_depth(c, context, depth + 1))
    {
        return false;
    }

    if let Some(not_cond) = &condition.not
        && evaluate_condition_depth(not_cond, context, depth + 1)
    {
        return false;
    }

    true
}

fn check_time_window(tw: &TimeWindowCondition, context: &RuntimeContext) -> bool {
    let now = resolve_current_time(context, tw.timezone.as_deref());
    let Some((hour, minute, day_of_week)) = now else {
        return false;
    };

    if !tw.days.is_empty() {
        let day_abbrev = day_abbreviation(day_of_week);
        if !tw.days.iter().any(|d| d.eq_ignore_ascii_case(day_abbrev)) {
            return false;
        }
    }

    let Some((start_h, start_m)) = parse_hhmm(&tw.start) else {
        return false;
    };
    let Some((end_h, end_m)) = parse_hhmm(&tw.end) else {
        return false;
    };

    let current_minutes = hour as u32 * 60 + minute as u32;
    let start_minutes = start_h as u32 * 60 + start_m as u32;
    let end_minutes = end_h as u32 * 60 + end_m as u32;

    if start_minutes == end_minutes {
        return true;
    }

    if start_minutes < end_minutes {
        current_minutes >= start_minutes && current_minutes < end_minutes
    } else {
        // Wraps midnight (e.g., 22:00 to 06:00)
        current_minutes >= start_minutes || current_minutes < end_minutes
    }
}

fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let hour: u8 = parts[0].parse().ok()?;
    let minute: u8 = parts[1].parse().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some((hour, minute))
}

fn day_abbreviation(day: u32) -> &'static str {
    match day {
        0 => "mon",
        1 => "tue",
        2 => "wed",
        3 => "thu",
        4 => "fri",
        5 => "sat",
        6 => "sun",
        _ => "mon", // fallback
    }
}

/// Returns `(hour, minute, day_of_week)` where day_of_week is 0=Mon..6=Sun.
fn resolve_current_time(context: &RuntimeContext, timezone: Option<&str>) -> Option<(u8, u8, u32)> {
    use chrono::{Datelike, NaiveDateTime, Timelike, Utc};

    let utc_now = if let Some(ref time_str) = context.current_time {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(time_str) {
            dt.with_timezone(&Utc)
        } else if let Ok(dt) = NaiveDateTime::parse_from_str(time_str, "%Y-%m-%dT%H:%M:%S") {
            dt.and_utc()
        } else {
            return None;
        }
    } else {
        Utc::now()
    };

    let tz = timezone.unwrap_or("UTC");
    let offset_minutes = parse_timezone_offset(tz);

    let adjusted = utc_now + chrono::Duration::minutes(offset_minutes as i64);
    let hour = adjusted.hour() as u8;
    let minute = adjusted.minute() as u8;
    let day_of_week = adjusted.weekday().num_days_from_monday();

    Some((hour, minute, day_of_week))
}

/// Parse a timezone identifier into an offset in minutes from UTC.
///
/// Supports:
/// - `"UTC"` -> 0
/// - `"+05:00"` / `"-05:30"` -> +300 / -330
/// - Common IANA names mapped to approximate fixed offsets.
///
/// For full IANA timezone support with DST, use the `chrono-tz` crate.
fn parse_timezone_offset(tz: &str) -> i32 {
    match tz {
        "UTC" | "utc" | "Etc/UTC" | "Etc/GMT" | "GMT" => 0,
        // US timezones (standard time -- DST not handled)
        "America/New_York" | "US/Eastern" | "EST" => -5 * 60,
        "America/Chicago" | "US/Central" | "CST" => -6 * 60,
        "America/Denver" | "US/Mountain" | "MST" => -7 * 60,
        "America/Los_Angeles" | "US/Pacific" | "PST" => -8 * 60,
        // Europe
        "Europe/London" | "GB" => 0,
        "Europe/Paris" | "Europe/Berlin" | "CET" => 60,
        "Europe/Helsinki" | "EET" => 120,
        // Asia
        "Asia/Tokyo" | "Japan" | "JST" => 9 * 60,
        "Asia/Shanghai" | "Asia/Hong_Kong" | "PRC" => 8 * 60,
        "Asia/Kolkata" | "Asia/Calcutta" | "IST" => 5 * 60 + 30,
        // Numeric offset
        _ => {
            if let Some(rest) = tz.strip_prefix('+') {
                parse_offset_value(rest)
            } else if let Some(rest) = tz.strip_prefix('-') {
                -parse_offset_value(rest)
            } else {
                0 // Unknown timezone, treat as UTC (fail-closed would deny, but we let the check continue)
            }
        }
    }
}

fn parse_offset_value(s: &str) -> i32 {
    if let Some((hours, minutes)) = s.split_once(':') {
        let hours = hours.parse::<i32>().unwrap_or(0);
        let minutes = minutes.parse::<i32>().unwrap_or(0);
        hours.saturating_mul(60).saturating_add(minutes)
    } else {
        s.parse::<i32>().unwrap_or(0).saturating_mul(60)
    }
}

/// Check whether the runtime context matches all required key-value pairs.
///
/// Keys are dot-delimited paths into the runtime context (e.g., `"environment"`,
/// `"user.role"`, `"agent.capabilities"`).
fn check_context_match(
    expected: &HashMap<String, serde_json::Value>,
    context: &RuntimeContext,
) -> bool {
    for (key, expected_value) in expected {
        let actual = resolve_context_value(key, context);
        if !match_value(&actual, expected_value) {
            return false;
        }
    }
    true
}

/// Resolve a dot-delimited path to a value in the runtime context.
fn resolve_context_value(path: &str, context: &RuntimeContext) -> Option<serde_json::Value> {
    let (namespace, subkey) = match path.split_once('.') {
        Some((ns, key)) => (ns, Some(key)),
        None => (path, None),
    };

    match namespace {
        "environment" => context
            .environment
            .as_ref()
            .map(|s| serde_json::Value::String(s.clone())),
        "user" => resolve_map_field(&context.user, subkey),
        "deployment" => resolve_map_field(&context.deployment, subkey),
        "agent" => resolve_map_field(&context.agent, subkey),
        "session" => resolve_map_field(&context.session, subkey),
        "request" => resolve_map_field(&context.request, subkey),
        "custom" => resolve_map_field(&context.custom, subkey),
        _ => None,
    }
}

fn resolve_map_field(
    map: &HashMap<String, serde_json::Value>,
    subkey: Option<&str>,
) -> Option<serde_json::Value> {
    match subkey {
        Some(key) => map.get(key).cloned(),
        None => Some(serde_json::to_value(map).unwrap_or_default()),
    }
}

/// Match an actual context value against an expected value.
///
/// Matching rules:
/// - String: exact equality
/// - Boolean: exact equality
/// - Integer: exact numeric equality
/// - Array of strings (expected): actual must be one of the listed values
/// - Scalar expected vs array actual: true if scalar is a member of the array
fn match_value(actual: &Option<serde_json::Value>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        // Missing context field -> fail-closed (condition fails).
        return false;
    };

    match expected {
        serde_json::Value::String(expected_str) => {
            match actual {
                serde_json::Value::String(actual_str) => actual_str == expected_str,
                // Scalar expected vs array actual: membership check
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .any(|v| v.as_str() == Some(expected_str.as_str())),
                _ => false,
            }
        }
        serde_json::Value::Bool(expected_bool) => actual.as_bool() == Some(*expected_bool),
        serde_json::Value::Number(expected_num) => {
            if let Some(expected_i64) = expected_num.as_i64() {
                actual.as_i64() == Some(expected_i64)
            } else if let Some(expected_f64) = expected_num.as_f64() {
                actual
                    .as_f64()
                    .is_some_and(|n| (n - expected_f64).abs() < f64::EPSILON)
            } else {
                false
            }
        }
        serde_json::Value::Array(expected_arr) => {
            // Array of expected values: actual must be one of them (OR).
            actual
                .as_str()
                .is_some_and(|actual_s| expected_arr.iter().any(|v| v.as_str() == Some(actual_s)))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with_env(env: &str) -> RuntimeContext {
        RuntimeContext {
            environment: Some(env.to_string()),
            ..Default::default()
        }
    }

    fn ctx_with_time(time: &str) -> RuntimeContext {
        RuntimeContext {
            current_time: Some(time.to_string()),
            ..Default::default()
        }
    }

    fn ctx_with_user_role(role: &str) -> RuntimeContext {
        let mut user = HashMap::new();
        user.insert(
            "role".to_string(),
            serde_json::Value::String(role.to_string()),
        );
        RuntimeContext {
            user,
            ..Default::default()
        }
    }

    #[test]
    fn context_condition_matches_environment() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
    }

    #[test]
    fn context_condition_rejects_mismatch() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(!evaluate_condition(&cond, &ctx_with_env("staging")));
    }

    #[test]
    fn context_condition_missing_field_fails_closed() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "user.role".to_string(),
                serde_json::Value::String("admin".to_string()),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };
        // Empty context -- missing field should fail.
        assert!(!evaluate_condition(&cond, &RuntimeContext::default()));
    }

    #[test]
    fn context_condition_matches_user_role() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "user.role".to_string(),
                serde_json::Value::String("admin".to_string()),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx_with_user_role("admin")));
        assert!(!evaluate_condition(&cond, &ctx_with_user_role("viewer")));
    }

    #[test]
    fn context_condition_array_or_match() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::json!(["production", "staging"]),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
        assert!(evaluate_condition(&cond, &ctx_with_env("staging")));
        assert!(!evaluate_condition(&cond, &ctx_with_env("development")));
    }

    #[test]
    fn context_condition_scalar_vs_array_membership() {
        // When the context field is an array and expected is a scalar,
        // true if scalar is in the array.
        let mut user = HashMap::new();
        user.insert(
            "groups".to_string(),
            serde_json::json!(["engineering", "ml-team"]),
        );
        let ctx = RuntimeContext {
            user,
            ..Default::default()
        };
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "user.groups".to_string(),
                serde_json::Value::String("ml-team".to_string()),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_matches_during_business_hours() {
        // Wednesday 2026-01-14 at 10:30 UTC
        let ctx = ctx_with_time("2026-01-14T10:30:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_rejects_outside_hours() {
        // Wednesday 2026-01-14 at 20:00 UTC
        let ctx = ctx_with_time("2026-01-14T20:00:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_day_filter() {
        // 2026-01-14 is a Wednesday
        let ctx = ctx_with_time("2026-01-14T10:00:00Z");

        let cond_weekday = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![
                    "mon".to_string(),
                    "tue".to_string(),
                    "wed".to_string(),
                    "thu".to_string(),
                    "fri".to_string(),
                ],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond_weekday, &ctx));

        let cond_weekend = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec!["sat".to_string(), "sun".to_string()],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(!evaluate_condition(&cond_weekend, &ctx));
    }

    #[test]
    fn time_window_wraps_midnight() {
        // 23:00 UTC
        let ctx_late = ctx_with_time("2026-01-14T23:00:00Z");
        // 03:00 UTC
        let ctx_early = ctx_with_time("2026-01-14T03:00:00Z");
        // 10:00 UTC (outside)
        let ctx_mid = ctx_with_time("2026-01-14T10:00:00Z");

        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "22:00".to_string(),
                end: "06:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx_late));
        assert!(evaluate_condition(&cond, &ctx_early));
        assert!(!evaluate_condition(&cond, &ctx_mid));
    }

    #[test]
    fn time_window_same_start_end_means_all_day() {
        let ctx = ctx_with_time("2026-01-14T03:00:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "12:00".to_string(),
                end: "12:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_honors_fractional_named_timezone_offsets() {
        // 04:00 UTC is 09:30 in Asia/Kolkata.
        let ctx = ctx_with_time("2026-01-14T04:00:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:30".to_string(),
                end: "10:00".to_string(),
                timezone: Some("Asia/Kolkata".to_string()),
                days: vec![],
            }),
            ..Default::default()
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_honors_fractional_numeric_timezone_offsets() {
        // 04:00 UTC is 09:30 at +05:30.
        let ctx = ctx_with_time("2026-01-14T04:00:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:30".to_string(),
                end: "10:00".to_string(),
                timezone: Some("+05:30".to_string()),
                days: vec![],
            }),
            ..Default::default()
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn all_of_requires_all_conditions() {
        let cond = Condition {
            time_window: None,
            context: None,
            all_of: Some(vec![
                Condition {
                    context: Some(HashMap::from([(
                        "environment".to_string(),
                        serde_json::Value::String("production".to_string()),
                    )])),
                    ..Default::default()
                },
                Condition {
                    context: Some(HashMap::from([(
                        "user.role".to_string(),
                        serde_json::Value::String("admin".to_string()),
                    )])),
                    ..Default::default()
                },
            ]),
            any_of: None,
            not: None,
        };

        let mut ctx = ctx_with_env("production");
        ctx.user.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        assert!(evaluate_condition(&cond, &ctx));

        // Only environment matches, not role
        assert!(!evaluate_condition(&cond, &ctx_with_env("production")));
    }

    #[test]
    fn any_of_requires_any_condition() {
        let cond = Condition {
            time_window: None,
            context: None,
            all_of: None,
            any_of: Some(vec![
                Condition {
                    context: Some(HashMap::from([(
                        "environment".to_string(),
                        serde_json::Value::String("production".to_string()),
                    )])),
                    ..Default::default()
                },
                Condition {
                    context: Some(HashMap::from([(
                        "environment".to_string(),
                        serde_json::Value::String("staging".to_string()),
                    )])),
                    ..Default::default()
                },
            ]),
            not: None,
        };

        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
        assert!(evaluate_condition(&cond, &ctx_with_env("staging")));
        assert!(!evaluate_condition(&cond, &ctx_with_env("development")));
    }

    #[test]
    fn not_negates_condition() {
        let cond = Condition {
            time_window: None,
            context: None,
            all_of: None,
            any_of: None,
            not: Some(Box::new(Condition {
                context: Some(HashMap::from([(
                    "environment".to_string(),
                    serde_json::Value::String("production".to_string()),
                )])),
                ..Default::default()
            })),
        };

        assert!(!evaluate_condition(&cond, &ctx_with_env("production")));
        assert!(evaluate_condition(&cond, &ctx_with_env("staging")));
    }

    #[test]
    fn nested_compound_conditions() {
        // Business hours AND production AND (admin OR sre)
        let cond = Condition {
            time_window: None,
            context: None,
            all_of: Some(vec![
                Condition {
                    time_window: Some(TimeWindowCondition {
                        start: "09:00".to_string(),
                        end: "17:00".to_string(),
                        timezone: Some("UTC".to_string()),
                        days: vec![],
                    }),
                    ..Default::default()
                },
                Condition {
                    context: Some(HashMap::from([(
                        "environment".to_string(),
                        serde_json::Value::String("production".to_string()),
                    )])),
                    ..Default::default()
                },
                Condition {
                    any_of: Some(vec![
                        Condition {
                            context: Some(HashMap::from([(
                                "user.role".to_string(),
                                serde_json::Value::String("admin".to_string()),
                            )])),
                            ..Default::default()
                        },
                        Condition {
                            context: Some(HashMap::from([(
                                "user.role".to_string(),
                                serde_json::Value::String("sre".to_string()),
                            )])),
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                },
            ]),
            any_of: None,
            not: None,
        };

        // 10:00 UTC Wed, production, admin
        let mut ctx = RuntimeContext {
            environment: Some("production".to_string()),
            current_time: Some("2026-01-14T10:00:00Z".to_string()),
            ..Default::default()
        };
        ctx.user.insert(
            "role".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        assert!(evaluate_condition(&cond, &ctx));

        // Same but "viewer" role -- should fail
        ctx.user.insert(
            "role".to_string(),
            serde_json::Value::String("viewer".to_string()),
        );
        assert!(!evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn max_nesting_depth_exceeded() {
        // Build a deeply nested condition that exceeds MAX_NESTING_DEPTH
        let mut cond = Condition {
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            ..Default::default()
        };
        for _ in 0..=MAX_NESTING_DEPTH + 1 {
            cond = Condition {
                all_of: Some(vec![cond]),
                ..Default::default()
            };
        }
        // Should fail because nesting depth is exceeded.
        assert!(!evaluate_condition(&cond, &ctx_with_env("production")));
    }

    #[test]
    fn condition_serialization_roundtrip() {
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec!["mon".to_string(), "fri".to_string()],
            }),
            context: Some(HashMap::from([(
                "environment".to_string(),
                serde_json::Value::String("production".to_string()),
            )])),
            all_of: None,
            any_of: None,
            not: None,
        };

        let yaml = serde_yaml::to_string(&cond).unwrap();
        let parsed: Condition = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cond, parsed);
    }

    #[test]
    fn empty_condition_always_true() {
        let cond = Condition {
            time_window: None,
            context: None,
            all_of: None,
            any_of: None,
            not: None,
        };
        assert!(evaluate_condition(&cond, &RuntimeContext::default()));
    }
}
