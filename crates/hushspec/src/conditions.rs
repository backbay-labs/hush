//! Conditional rules system for HushSpec (core spec 3.13).
//!
//! A `Condition` gates whether a rule block is active. Conditions are a
//! document field (`when`) on every rule block; the out-of-band map accepted by
//! [`evaluate_with_context`](crate::evaluate_with_context) is kept as an
//! override that is ANDed with each block's own `when`.
//!
//! Design principles:
//! - **Fail-closed toward enforcement**: a missing context field makes the
//!   condition false (the block goes inert), but a condition the engine cannot
//!   evaluate at all -- unresolvable time zone, unparsable `current_time`, a
//!   malformed `HH:MM` that escaped validation, or nesting past the depth cap --
//!   leaves the block ACTIVE.
//! - **Deterministic**: same context + condition = same result, always.
//! - **Not Turing-complete**: fixed predicate types composed with AND/OR/NOT.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum allowed nesting depth for compound conditions (core spec 3.13).
pub const MAX_NESTING_DEPTH: usize = 8;

/// Day abbreviations accepted in `time_window.days`.
pub const DAY_ABBREVIATIONS: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

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

    /// The effective posture state must grant this capability (core spec
    /// 3.13). Unevaluable -- and therefore held -- when the policy has no
    /// posture extension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,

    /// A runtime counter compared against a threshold (core spec 3.13).
    /// Unevaluable -- and therefore held -- when the context carries no such
    /// counter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<RateCondition>,
}

/// Rate condition: compares an engine-supplied counter with a threshold.
///
/// HushSpec never stores state; the engine owns the window and supplies the
/// current count in `RuntimeContext::counters`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateCondition {
    /// Name of the counter in `RuntimeContext::counters`.
    pub counter: String,
    /// Non-negative threshold the counter is compared against.
    pub threshold: u64,
    /// `gte`: true when `counter >= threshold`; `lt`: true when `counter < threshold`.
    pub comparison: RateComparison,
}

/// How a [`RateCondition`] compares the counter with its threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateComparison {
    /// The counter is at or above the threshold.
    Gte,
    /// The counter is below the threshold.
    Lt,
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
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Engine-maintained counters consulted by `rate` conditions (core spec
    /// 3.13). The engine owns the window; HushSpec only compares.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub counters: HashMap<String, u64>,

    /// Current time override for testing (ISO 8601).
    /// If `None`, the system clock is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_time: Option<String>,
}

/// Whether a block gated by `condition` is active: `true` unless the
/// condition evaluates to `false` (core spec 3.13).
///
/// Missing context fields make a `context` predicate false. A predicate the
/// engine cannot evaluate is unevaluable and holds, so the block stays active;
/// `not`, `all_of` and `any_of` propagate unevaluable rather than turning it
/// into a boolean.
///
/// A `capability` predicate is unevaluable through this entry point (no
/// posture state is known); use [`evaluate_condition_with_capabilities`] from
/// an evaluator that has resolved the effective posture state.
pub fn evaluate_condition(condition: &Condition, context: &RuntimeContext) -> bool {
    evaluate_condition_depth(condition, context, None, 0).is_active()
}

/// [`evaluate_condition`] with the capabilities the effective posture state
/// grants: `None` when the policy has no posture extension (a `capability`
/// predicate is then unevaluable and holds), `Some(list)` otherwise (an
/// unknown state grants nothing, so the predicate is false).
pub fn evaluate_condition_with_capabilities(
    condition: &Condition,
    context: &RuntimeContext,
    capabilities: Option<&[String]>,
) -> bool {
    evaluate_condition_depth(condition, context, capabilities, 0).is_active()
}

/// What a condition evaluates to (core spec 3.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    True,
    False,
    /// The engine lacks what the predicate needs -- a posture extension, a
    /// counter, a clock it can read. Never switches a block off.
    Unevaluable,
}

impl Verdict {
    fn from_bool(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }

    /// A block is inert only on an evaluated `false`.
    fn is_active(self) -> bool {
        self != Self::False
    }

    fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unevaluable => Self::Unevaluable,
        }
    }

    /// AND: `false` wins, then unevaluable, then `true`.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::Unevaluable, _) | (_, Self::Unevaluable) => Self::Unevaluable,
            (Self::True, Self::True) => Self::True,
        }
    }

    /// OR: `true` wins, then unevaluable, then `false`.
    fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::True, _) | (_, Self::True) => Self::True,
            (Self::Unevaluable, _) | (_, Self::Unevaluable) => Self::Unevaluable,
            (Self::False, Self::False) => Self::False,
        }
    }
}

/// Parse-time validation of a condition (core spec 3.13): unknown keys are
/// rejected by serde; this checks `HH:MM` fields, the timezone, the day
/// abbreviations, and the nesting depth. Returns one message per violation,
/// each prefixed with `path` (for example `rules.egress.when`).
pub fn validate_condition(condition: &Condition, path: &str) -> Vec<String> {
    let mut errors = Vec::new();
    validate_condition_depth(condition, path, 0, &mut errors);
    errors
}

fn validate_condition_depth(
    condition: &Condition,
    path: &str,
    depth: usize,
    errors: &mut Vec<String>,
) {
    if depth > MAX_NESTING_DEPTH {
        errors.push(format!(
            "{path}: conditions nest deeper than the maximum of {MAX_NESTING_DEPTH} levels"
        ));
        return;
    }
    if let Some(tw) = &condition.time_window {
        for (field, value) in [("start", &tw.start), ("end", &tw.end)] {
            if parse_hhmm(value).is_none() {
                errors.push(format!(
                    "{path}.time_window.{field}: {value:?} is not a valid HH:MM time"
                ));
            }
        }
        if let Some(tz) = tw.timezone.as_deref()
            && !timezone_is_known(tz)
        {
            errors.push(format!(
                "{path}.time_window.timezone: {tz:?} is neither an IANA time zone nor a fixed offset"
            ));
        }
        for day in &tw.days {
            if !DAY_ABBREVIATIONS
                .iter()
                .any(|known| day.eq_ignore_ascii_case(known))
            {
                errors.push(format!(
                    "{path}.time_window.days: {day:?} is not one of mon, tue, wed, thu, fri, sat, sun"
                ));
            }
        }
    }
    if let Some(name) = &condition.capability
        && !is_capability_identifier(name)
    {
        errors.push(format!(
            "{path}.capability: {name:?} is not a capability identifier (lowercase ASCII letters, digits and underscores in dot-separated segments that start with a letter)"
        ));
    }
    if let Some(rate) = &condition.rate
        && !is_capability_identifier(&rate.counter)
    {
        errors.push(format!(
            "{path}.rate.counter: {:?} is not a counter identifier (lowercase ASCII letters, digits and underscores in dot-separated segments that start with a letter)",
            rate.counter
        ));
    }
    if let Some(all) = &condition.all_of {
        for (index, child) in all.iter().enumerate() {
            validate_condition_depth(child, &format!("{path}.all_of[{index}]"), depth + 1, errors);
        }
    }
    if let Some(any) = &condition.any_of {
        for (index, child) in any.iter().enumerate() {
            validate_condition_depth(child, &format!("{path}.any_of[{index}]"), depth + 1, errors);
        }
    }
    if let Some(not) = &condition.not {
        validate_condition_depth(not, &format!("{path}.not"), depth + 1, errors);
    }
}

/// The identifier grammar shared by posture capabilities and rate counters
/// (core spec 3.13): one or more dot-separated segments, each a lowercase
/// ASCII letter followed by lowercase letters, digits or underscores.
pub fn is_capability_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|segment| {
            let mut chars = segment.chars();
            matches!(chars.next(), Some('a'..='z'))
                && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
        })
}

/// Whether `tz` is an IANA identifier known to this engine, a known alias, or
/// a fixed `+HH:MM` / `-HH:MM` offset.
pub fn timezone_is_known(tz: &str) -> bool {
    use std::str::FromStr;
    chrono_tz::Tz::from_str(tz).is_ok() || parse_timezone_offset(tz).is_some()
}

fn evaluate_condition_depth(
    condition: &Condition,
    context: &RuntimeContext,
    capabilities: Option<&[String]>,
    depth: usize,
) -> Verdict {
    if depth > MAX_NESTING_DEPTH {
        // Validation rejects this at parse time; an out-of-band condition that
        // exceeds the depth cannot be evaluated, and an unevaluable condition
        // must not switch a control off (core spec 3.13).
        return Verdict::Unevaluable;
    }

    // The fields of one condition object are ANDed. An evaluated `false`
    // settles the object, so later fields are not consulted.
    let mut verdict = Verdict::True;

    if let Some(tw) = &condition.time_window {
        verdict = verdict.and(check_time_window(tw, context));
        if verdict == Verdict::False {
            return verdict;
        }
    }

    if let Some(ctx) = &condition.context {
        verdict = verdict.and(Verdict::from_bool(check_context_match(ctx, context)));
        if verdict == Verdict::False {
            return verdict;
        }
    }

    // `capability`: unevaluable without a posture extension; otherwise the
    // effective state must list the capability.
    if let Some(name) = &condition.capability {
        verdict = verdict.and(match capabilities {
            None => Verdict::Unevaluable,
            Some(granted) => Verdict::from_bool(granted.iter().any(|granted| granted == name)),
        });
        if verdict == Verdict::False {
            return verdict;
        }
    }

    // `rate`: unevaluable when the engine supplied no such counter.
    if let Some(rate) = &condition.rate {
        verdict = verdict.and(match context.counters.get(&rate.counter) {
            None => Verdict::Unevaluable,
            Some(&count) => Verdict::from_bool(match rate.comparison {
                RateComparison::Gte => count >= rate.threshold,
                RateComparison::Lt => count < rate.threshold,
            }),
        });
        if verdict == Verdict::False {
            return verdict;
        }
    }

    if let Some(all) = &condition.all_of {
        let combined = all.iter().fold(Verdict::True, |acc, c| {
            acc.and(evaluate_condition_depth(
                c,
                context,
                capabilities,
                depth + 1,
            ))
        });
        verdict = verdict.and(combined);
        if verdict == Verdict::False {
            return verdict;
        }
    }

    if let Some(any) = &condition.any_of
        && !any.is_empty()
    {
        let combined = any.iter().fold(Verdict::False, |acc, c| {
            acc.or(evaluate_condition_depth(
                c,
                context,
                capabilities,
                depth + 1,
            ))
        });
        verdict = verdict.and(combined);
        if verdict == Verdict::False {
            return verdict;
        }
    }

    if let Some(not_cond) = &condition.not {
        verdict = verdict
            .and(evaluate_condition_depth(not_cond, context, capabilities, depth + 1).negate());
    }

    verdict
}

fn check_time_window(tw: &TimeWindowCondition, context: &RuntimeContext) -> Verdict {
    // A window the engine cannot evaluate -- unresolvable time zone,
    // unparsable current_time, or a malformed HH:MM that escaped validation --
    // is unevaluable and leaves the block active (core spec 3.13).
    let now = resolve_current_time(context, tw.timezone.as_deref());
    let Some((hour, minute, day_of_week)) = now else {
        return Verdict::Unevaluable;
    };

    let Some((start_h, start_m)) = parse_hhmm(&tw.start) else {
        return Verdict::Unevaluable;
    };
    let Some((end_h, end_m)) = parse_hhmm(&tw.end) else {
        return Verdict::Unevaluable;
    };

    let current_minutes = hour as u32 * 60 + minute as u32;
    let start_minutes = start_h as u32 * 60 + start_m as u32;
    let end_minutes = end_h as u32 * 60 + end_m as u32;
    let wraps_midnight = start_minutes > end_minutes;

    if !tw.days.is_empty() {
        let effective_day = if wraps_midnight && current_minutes < end_minutes {
            (day_of_week + 6) % 7
        } else {
            day_of_week
        };
        let day_abbrev = day_abbreviation(effective_day);
        if !tw.days.iter().any(|d| d.eq_ignore_ascii_case(day_abbrev)) {
            return Verdict::False;
        }
    }

    if start_minutes == end_minutes {
        return Verdict::True;
    }

    Verdict::from_bool(if start_minutes < end_minutes {
        current_minutes >= start_minutes && current_minutes < end_minutes
    } else {
        // Wraps midnight (e.g., 22:00 to 06:00)
        current_minutes >= start_minutes || current_minutes < end_minutes
    })
}

/// A `time_window` bound, which is exactly two ASCII digits per component
/// (`schemas/hushspec-core.v1.schema.json` `$defs.TimeWindow`). `9:05`,
/// `09:5`, `009:05` and `+9:00` are all outside that shape, so they are not
/// times: validation refuses them and an evaluator that meets one leaves the
/// window unevaluable and the rule block active (core spec 3.13).
fn parse_hhmm(s: &str) -> Option<(u8, u8)> {
    let (hours, minutes) = s.split_once(':')?;
    let field = |part: &str| -> Option<u8> {
        let bytes = part.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some((bytes[0] - b'0') * 10 + (bytes[1] - b'0'))
    };
    let hour = field(hours)?;
    let minute = field(minutes)?;
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
    use chrono::{Datelike, FixedOffset, NaiveDateTime, Timelike, Utc};
    use std::str::FromStr;

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
    let adjusted = if let Ok(tz) = chrono_tz::Tz::from_str(tz) {
        utc_now.with_timezone(&tz).fixed_offset()
    } else {
        let offset_minutes = parse_timezone_offset(tz)?;
        let offset = FixedOffset::east_opt(offset_minutes.saturating_mul(60))?;
        utc_now.with_timezone(&offset)
    };
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
/// - Fixed aliases like `"EST"` or `"JST"`
///
/// IANA timezone names are resolved in `resolve_current_time` via `chrono-tz`.
fn parse_timezone_offset(tz: &str) -> Option<i32> {
    match tz {
        "UTC" | "utc" | "Etc/UTC" | "Etc/GMT" | "GMT" => Some(0),
        "US/Eastern" | "EST" => Some(-5 * 60),
        "US/Central" | "CST" => Some(-6 * 60),
        "US/Mountain" | "MST" => Some(-7 * 60),
        "US/Pacific" | "PST" => Some(-8 * 60),
        "GB" => Some(0),
        "CET" => Some(60),
        "EET" => Some(120),
        "Japan" | "JST" => Some(9 * 60),
        "PRC" => Some(8 * 60),
        "IST" => Some(5 * 60 + 30),
        // Numeric offset
        _ => {
            if let Some(rest) = tz.strip_prefix('+') {
                parse_offset_value(rest)
            } else if let Some(rest) = tz.strip_prefix('-') {
                parse_offset_value(rest).map(|value| -value)
            } else {
                None
            }
        }
    }
}

/// Minutes for a fixed offset body, the part of a `timezone` after its sign:
/// `HH` or `HH:MM`, two ASCII digits per field (core spec 3.13).
///
/// Anything else is not an offset. A zone that cannot be resolved leaves the
/// rule block active, so accepting a one-digit field, a missing colon or a
/// second sign here would resolve a zone another engine refuses and could
/// switch a control off.
fn parse_offset_value(s: &str) -> Option<i32> {
    let (hours, minutes) = match s.split_once(':') {
        Some((hours, minutes)) => (hours, minutes),
        None => (s, "00"),
    };
    let hours = parse_two_digits(hours)?;
    let minutes = parse_two_digits(minutes)?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(hours * 60 + minutes)
}

/// Exactly two ASCII digits as a number, or `None`.
fn parse_two_digits(field: &str) -> Option<i32> {
    match field.as_bytes() {
        [tens @ b'0'..=b'9', ones @ b'0'..=b'9'] => {
            Some(i32::from(tens - b'0') * 10 + i32::from(ones - b'0'))
        }
        _ => None,
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

/// Leaf-level scalar equality for a `context` predicate (core spec 3.13).
///
/// `expected` is always a non-array scalar here -- array unwrapping happens one
/// level up, in [`matches_scalar_or_membership`]. Strings and booleans compare
/// exactly, and a boolean is never numeric. Numbers compare by exact value with
/// no tolerance, so `0.3` does not match `0.30000000000000004`, and by value
/// alone: the integer `1` and the float `1.0` are the same number, whichever
/// spelling the document or the runtime context used.
fn values_equal(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match expected {
        serde_json::Value::String(expected_str) => actual.as_str() == Some(expected_str.as_str()),
        serde_json::Value::Bool(expected_bool) => actual.as_bool() == Some(*expected_bool),
        serde_json::Value::Number(expected_num) => match actual {
            serde_json::Value::Number(actual_num) => {
                match (actual_num.as_i64(), expected_num.as_i64()) {
                    (Some(a), Some(e)) => a == e,
                    _ => match (actual_num.as_f64(), expected_num.as_f64()) {
                        (Some(a), Some(e)) => a == e,
                        _ => false,
                    },
                }
            }
            _ => false,
        },
        _ => false,
    }
}

fn matches_scalar_or_membership(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match actual {
        serde_json::Value::Array(arr) => arr.iter().any(|item| values_equal(item, expected)),
        _ => values_equal(actual, expected),
    }
}

fn match_value(actual: &Option<serde_json::Value>, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        // Missing context field -> fail-closed (condition fails).
        return false;
    };

    match expected {
        serde_json::Value::String(_)
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_) => matches_scalar_or_membership(actual, expected),
        serde_json::Value::Array(expected_arr) => expected_arr
            .iter()
            .any(|candidate| matches_scalar_or_membership(actual, candidate)),
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
            capability: None,
            rate: None,
        };
        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
    }

    fn ctx_with_custom(key: &str, value: serde_json::Value) -> RuntimeContext {
        RuntimeContext {
            custom: HashMap::from([(key.to_string(), value)]),
            ..Default::default()
        }
    }

    fn context_condition(key: &str, expected: serde_json::Value) -> Condition {
        Condition {
            context: Some(HashMap::from([(key.to_string(), expected)])),
            ..Condition::default()
        }
    }

    #[test]
    fn context_numbers_compare_exactly() {
        let cond = context_condition("custom.ratio", serde_json::json!(0.3));
        assert!(evaluate_condition(
            &cond,
            &ctx_with_custom("ratio", serde_json::json!(0.3))
        ));
        assert!(!evaluate_condition(
            &cond,
            &ctx_with_custom("ratio", serde_json::json!(0.300_000_000_000_000_04))
        ));
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn context_condition_array_or_match_numbers() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "session.action_count".to_string(),
                serde_json::json!([1, 2, 3]),
            )])),
            all_of: None,
            any_of: None,
            not: None,
            capability: None,
            rate: None,
        };
        let ctx = RuntimeContext {
            session: HashMap::from([("action_count".to_string(), serde_json::json!(2))]),
            ..Default::default()
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn context_condition_array_or_match_booleans() {
        let cond = Condition {
            time_window: None,
            context: Some(HashMap::from([(
                "request.interactive".to_string(),
                serde_json::json!([true]),
            )])),
            all_of: None,
            any_of: None,
            not: None,
            capability: None,
            rate: None,
        };
        let ctx = RuntimeContext {
            request: HashMap::from([("interactive".to_string(), serde_json::json!(true))]),
            ..Default::default()
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
    fn time_window_wraps_midnight_with_day_filter() {
        // Saturday 2026-01-17 03:00 UTC should still count as Friday night.
        let ctx = ctx_with_time("2026-01-17T03:00:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "22:00".to_string(),
                end: "06:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec!["fri".to_string()],
            }),
            ..Default::default()
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_uses_dst_for_iana_timezones() {
        // 13:30 UTC is 09:30 in America/New_York on July 1, 2026.
        let ctx = ctx_with_time("2026-07-01T13:30:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "10:00".to_string(),
                timezone: Some("America/New_York".to_string()),
                days: vec![],
            }),
            ..Default::default()
        };
        assert!(evaluate_condition(&cond, &ctx));
    }

    #[test]
    fn time_window_leading_plus_start_keeps_block_active() {
        // A leading `+` in an HH:MM token (`+9:00`) must fail to parse, matching
        // the TS/Python parsers. Validation rejects it at parse time; if it
        // reaches evaluation the window cannot be evaluated, and an unevaluable
        // condition leaves the block ACTIVE (core spec 3.13), so the condition
        // holds rather than switching the control off.
        let ctx = ctx_with_time("2026-01-14T20:30:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "+9:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("UTC".to_string()),
                days: vec![],
            }),
            context: None,
            all_of: None,
            any_of: None,
            not: None,
            capability: None,
            rate: None,
        };
        assert!(evaluate_condition(&cond, &ctx));
        assert!(!validate_condition(&cond, "rules.x.when").is_empty());
    }

    #[test]
    fn fixed_offset_grammar_is_two_digit_fields() {
        for zone in ["+05:30", "-08:00", "+05", "-08", "+00:00"] {
            assert!(timezone_is_known(zone), "{zone} should conform");
        }
        // A zone the engine cannot resolve leaves the rule block active, so an
        // offset another engine refuses must not resolve here either.
        for zone in ["+5", "+0530", "+5:0", "++5", "+05:3", "+ 5:30", "+05:30 "] {
            assert!(!timezone_is_known(zone), "{zone} should be refused");
        }
    }

    #[test]
    fn time_window_invalid_timezone_keeps_block_active() {
        // An unresolvable time zone MUST NOT switch a security control off
        // (core spec 3.13): the window is treated as satisfied. Validation
        // rejects the zone at parse time.
        let ctx = ctx_with_time("2026-01-14T13:30:00Z");
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: Some("America/NeYork".to_string()),
                days: vec![],
            }),
            ..Default::default()
        };
        assert!(evaluate_condition(&cond, &ctx));
        let errors = validate_condition(&cond, "rules.x.when");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("timezone"), "{errors:?}");
    }

    #[test]
    fn validate_condition_reports_each_violation() {
        let cond = Condition {
            time_window: Some(TimeWindowCondition {
                start: "25:00".to_string(),
                end: "17:60".to_string(),
                timezone: Some("+05:30".to_string()),
                days: vec!["Mon".to_string(), "funday".to_string()],
            }),
            ..Default::default()
        };
        let errors = validate_condition(&cond, "rules.shell_commands.when");
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("time_window.start")));
        assert!(errors.iter().any(|e| e.contains("time_window.end")));
        assert!(errors.iter().any(|e| e.contains("funday")));

        let mut deep = Condition {
            context: Some(HashMap::new()),
            ..Default::default()
        };
        for _ in 0..(MAX_NESTING_DEPTH + 1) {
            deep = Condition {
                not: Some(Box::new(deep)),
                ..Default::default()
            };
        }
        let errors = validate_condition(&deep, "rules.egress.when");
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("nest deeper"), "{errors:?}");

        let mut ok = Condition {
            context: Some(HashMap::new()),
            ..Default::default()
        };
        for _ in 0..MAX_NESTING_DEPTH {
            ok = Condition {
                not: Some(Box::new(ok)),
                ..Default::default()
            };
        }
        assert!(validate_condition(&ok, "rules.egress.when").is_empty());
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
        };

        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
        assert!(evaluate_condition(&cond, &ctx_with_env("staging")));
        assert!(!evaluate_condition(&cond, &ctx_with_env("development")));
    }

    #[test]
    fn empty_any_of_is_treated_as_unset() {
        let cond = Condition {
            any_of: Some(vec![]),
            ..Default::default()
        };

        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
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
        // Validation rejects this document; if such a condition still reaches
        // evaluation (out-of-band map) it cannot be evaluated, and an
        // unevaluable condition leaves the block active (core spec 3.13).
        assert!(evaluate_condition(&cond, &ctx_with_env("production")));
        assert!(!validate_condition(&cond, "rules.x.when").is_empty());
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
            capability: None,
            rate: None,
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
            capability: None,
            rate: None,
        };
        assert!(evaluate_condition(&cond, &RuntimeContext::default()));
    }
}
