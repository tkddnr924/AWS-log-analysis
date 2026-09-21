//! Rule evaluation. A rule either matches with the values that fired, or does
//! not match — event data never produces an evaluation error.

use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::BTreeMap;

use serde_json::Value;

use super::{Condition, FieldCondition, Literal, Op, Rule};
use crate::model::NormalizedEvent;

/// A rule hit plus the evidence for it (docs/04 `matched_fields`).
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub rule_id: String,
    /// Variable name to the value that satisfied it.
    pub matched_fields: BTreeMap<String, String>,
}

/// Caches per-event work shared by every rule and field condition.
///
/// `request`/`response`/`resources`/`raw` are stored as JSON text. Parsing
/// them once per event instead of once per condition matters when rules ×
/// events reaches millions.
pub struct EventView<'a> {
    event: &'a NormalizedEvent,
    request: OnceCell<Option<Value>>,
    response: OnceCell<Option<Value>>,
    resources: OnceCell<Option<Value>>,
    raw: OnceCell<Option<Value>>,
    /// `event_time` as RFC 3339 text: the only field that has to be formatted,
    /// so it is formatted at most once per event rather than per condition.
    time: OnceCell<Option<String>>,
}

impl<'a> EventView<'a> {
    pub fn new(event: &'a NormalizedEvent) -> Self {
        Self {
            event,
            request: OnceCell::new(),
            response: OnceCell::new(),
            resources: OnceCell::new(),
            raw: OnceCell::new(),
            time: OnceCell::new(),
        }
    }

    fn json(&self, column: &str) -> Option<&Value> {
        let (cell, text) = match column {
            "request" => (&self.request, &self.event.request),
            "response" => (&self.response, &self.event.response),
            "resources" => (&self.resources, &self.event.resources),
            "raw" => (&self.raw, &self.event.raw),
            _ => return None,
        };
        cell.get_or_init(|| {
            text.as_deref()
                .and_then(|json| serde_json::from_str(json).ok())
        })
        .as_ref()
    }

    fn time(&self) -> Option<&str> {
        self.time
            .get_or_init(|| {
                self.event.event_time.map(|at| {
                    at.format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default()
                })
            })
            .as_deref()
    }
}

/// A field value borrowed from the event or from its parsed JSON.
///
/// Rendering text and cloning JSON subtrees is what an evaluation over tens of
/// millions of events pays for, so both are deferred until a condition really
/// needs them — on the rejecting path, never.
#[derive(Debug, Clone, Copy)]
enum Val<'a> {
    Text(&'a str),
    Bool(bool),
    /// What is left once strings and booleans are named: numbers, arrays and
    /// objects out of a JSON column.
    Json(&'a Value),
}

impl<'a> Val<'a> {
    fn json(value: &'a Value) -> Self {
        match value {
            Value::String(text) => Val::Text(text),
            Value::Bool(flag) => Val::Bool(*flag),
            other => Val::Json(other),
        }
    }

    /// The text form the string operators and the evidence use. Borrowed for
    /// every scalar; only numbers and containers allocate.
    fn text(self) -> Cow<'a, str> {
        match self {
            Val::Text(text) => Cow::Borrowed(text),
            Val::Bool(true) => Cow::Borrowed("true"),
            Val::Bool(false) => Cow::Borrowed("false"),
            Val::Json(value) => Cow::Owned(value.to_string()),
        }
    }

    fn number(self) -> Option<f64> {
        match self {
            // Timestamps and numeric strings still compare numerically.
            Val::Text(text) => text.parse().ok(),
            Val::Json(Value::Number(number)) => number.as_f64(),
            Val::Bool(_) | Val::Json(_) => None,
        }
    }
}

/// Why a field condition held. `missing` fired on nothing at all, and its
/// evidence is empty text.
enum Fired<'a> {
    Absent,
    Value(Val<'a>),
}

impl Fired<'_> {
    fn evidence(self) -> String {
        match self {
            Fired::Absent => String::new(),
            Fired::Value(value) => value.text().into_owned(),
        }
    }
}

/// True when any rule matches. Shares one `EventView` across the set and never
/// builds evidence, which is all a rule-count preview needs.
pub fn evaluate_any<'a>(
    rules: impl IntoIterator<Item = &'a Rule>,
    event: &NormalizedEvent,
) -> bool {
    let view = EventView::new(event);
    rules.into_iter().any(|rule| matches_view(rule, &view))
}

/// Evaluates one rule against one event. Prefer [`evaluate_view`] when several
/// rules run against the same event.
pub fn evaluate(rule: &Rule, event: &NormalizedEvent) -> Option<Match> {
    evaluate_view(rule, &EventView::new(event))
}

/// Evaluates one rule against a cached event view.
pub fn evaluate_view(rule: &Rule, view: &EventView<'_>) -> Option<Match> {
    // The evidence first: a rule that did not fire must not pay for the id.
    let matched_fields = evidence(rule, view)?;
    Some(Match {
        rule_id: rule.id.clone(),
        matched_fields,
    })
}

/// The evidence a hit carries, for callers that already know which rule fired
/// and would only drop a clone of its id.
pub(super) fn evidence(rule: &Rule, view: &EventView<'_>) -> Option<BTreeMap<String, String>> {
    let mut lazy = Lazy::new(rule, view);
    if !holds(&rule.condition, &mut lazy) {
        return None;
    }

    // Every field that fired, not only the ones the condition consulted, so
    // the results view can explain the whole rule. The ones the lazy pass
    // already rejected cannot contribute and are not run again; the ones that
    // held are, to read their value back out.
    let mut satisfied = BTreeMap::new();
    for (index, field) in rule.fields.iter().enumerate() {
        if lazy.rejected(index) {
            continue;
        }
        if let Some(fired) = check(field, view) {
            satisfied.insert(field.var.clone(), fired.evidence());
        }
    }

    Some(satisfied)
}

/// Decides a rule without building any evidence.
fn matches_view(rule: &Rule, view: &EventView<'_>) -> bool {
    holds(&rule.condition, &mut Lazy::new(rule, view))
}

/// The memo bit for a field condition, when it has one.
fn memo(index: usize) -> Option<u64> {
    (index < 64).then(|| 1u64 << index)
}

/// Runs field conditions on demand: the condition decides which ones are
/// needed, so `$a and $b` never pays for `$b` once `$a` failed, and a field
/// the condition does not name is not touched while rejecting.
struct Lazy<'r, 'v> {
    fields: &'r [FieldCondition],
    view: &'v EventView<'v>,
    /// One bit per field condition, indexed as in `fields`: `known` marks the
    /// ones already run and `held` the ones that fired. Rules carry a handful
    /// of fields; beyond 64 the memo stops caching and a repeated variable is
    /// simply re-run.
    known: u64,
    held: u64,
}

impl<'r, 'v> Lazy<'r, 'v> {
    fn new(rule: &'r Rule, view: &'v EventView<'v>) -> Self {
        Self {
            fields: &rule.fields,
            view,
            known: 0,
            held: 0,
        }
    }

    /// True when field `index` was already run and did not hold, so it cannot
    /// appear in the evidence either.
    fn rejected(&self, index: usize) -> bool {
        let Some(bit) = memo(index) else {
            return false;
        };
        self.known & bit != 0 && self.held & bit == 0
    }

    /// True when any field condition bound to `var` holds — a condition only
    /// ever asks whether a variable fired, never with which value, so the
    /// first one that holds ends the search.
    fn var(&mut self, var: &str) -> bool {
        // Copied out so the loop can record verdicts on `self` while running.
        let (fields, view) = (self.fields, self.view);
        for (index, field) in fields.iter().enumerate() {
            if field.var != var {
                continue;
            }
            let bit = memo(index);
            if let Some(bit) = bit {
                if self.known & bit != 0 {
                    if self.held & bit != 0 {
                        return true;
                    }
                    continue;
                }
            }
            let held = check(field, view).is_some();
            if let Some(bit) = bit {
                self.known |= bit;
                if held {
                    self.held |= bit;
                }
            }
            if held {
                return true;
            }
        }
        false
    }
}

fn holds(condition: &Condition, lazy: &mut Lazy<'_, '_>) -> bool {
    match condition {
        Condition::Var(var) => lazy.var(var),
        Condition::Not(inner) => !holds(inner, lazy),
        Condition::And(a, b) => holds(a, lazy) && holds(b, lazy),
        Condition::Or(a, b) => holds(a, lazy) || holds(b, lazy),
        Condition::NOf(count, vars) => {
            // Each listed entry counts on its own, so `2 of ($a, $a)` is met
            // by `$a` alone. Stops as soon as the count is reached, or once
            // what is left cannot reach it.
            let mut hits = 0usize;
            let mut left = vars.len();
            for var in vars {
                if hits >= *count {
                    return true;
                }
                if hits + left < *count {
                    return false;
                }
                hits += usize::from(lazy.var(var));
                left -= 1;
            }
            hits >= *count
        }
    }
}

/// Returns why the condition held, or `None` when it did not.
fn check<'v>(condition: &FieldCondition, view: &'v EventView<'v>) -> Option<Fired<'v>> {
    let actual = resolve(&condition.field, view);

    match condition.op {
        Op::Exists => return actual.map(Fired::Value),
        Op::Missing => return actual.is_none().then_some(Fired::Absent),
        _ => {}
    }

    // An absent field never satisfies a value comparison.
    let actual = actual?;

    let satisfied = match condition.op {
        Op::Eq => equals(actual, &condition.value),
        Op::Ne => !equals(actual, &condition.value),
        Op::Contains
        | Op::IContains
        | Op::StartsWith
        | Op::IStartsWith
        | Op::EndsWith
        | Op::IEndsWith => substring(actual, condition),
        // Pre-compiled at parse time.
        Op::Matches => match &condition.value {
            Literal::Regex(re) => re.is_match(&actual.text()),
            _ => false,
        },
        Op::In => match &condition.value {
            Literal::Set(items) => {
                let text = actual.text();
                items.iter().any(|item| item.as_str() == &*text)
            }
            _ => false,
        },
        Op::Gt | Op::Ge | Op::Lt | Op::Le => compare(actual, condition),
        Op::Exists | Op::Missing => unreachable!("handled above"),
    };

    satisfied.then_some(Fired::Value(actual))
}

/// The substring family. The case-insensitive operators fold ASCII where the
/// old form lowercased both sides into fresh strings; ASCII lowercasing is
/// length-preserving, so the two agree on every input, including the
/// multi-byte UTF-8 neither form touches.
fn substring(actual: Val<'_>, condition: &FieldCondition) -> bool {
    let Some(needle) = condition.value.as_str() else {
        return false;
    };
    let text = actual.text();

    match condition.op {
        Op::Contains => text.contains(needle),
        Op::StartsWith => text.starts_with(needle),
        Op::EndsWith => text.ends_with(needle),
        Op::IContains => contains_ascii_case(&text, needle),
        Op::IStartsWith => {
            let (haystack, needle) = (text.as_bytes(), needle.as_bytes());
            haystack.len() >= needle.len() && haystack[..needle.len()].eq_ignore_ascii_case(needle)
        }
        Op::IEndsWith => {
            let (haystack, needle) = (text.as_bytes(), needle.as_bytes());
            haystack.len() >= needle.len()
                && haystack[haystack.len() - needle.len()..].eq_ignore_ascii_case(needle)
        }
        other => unreachable!("not a substring operator: {other:?}"),
    }
}

/// Above this many bytes, folding into a copy and running the vectorized
/// substring search over it beats scanning in place. Measured on aarch64: the
/// scan costs ~0.7 ns/byte against ~0.2 ns/byte for copy-and-search plus ~45 ns
/// of allocation, and the two cross at about a hundred bytes.
const FOLD_INTO_COPY_ABOVE: usize = 96;

/// `haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())`.
///
/// A normalized field — user agent, ARN, event name — is short enough to fold
/// in place and allocate nothing at all. A whole `raw` record is not, so it
/// keeps the copy rather than paying a scalar scan per event.
fn contains_ascii_case(haystack: &str, needle: &str) -> bool {
    if haystack.len() > FOLD_INTO_COPY_ABOVE {
        return haystack
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase());
    }

    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    let Some((first, rest)) = needle.split_first() else {
        return true;
    };
    let first = first.to_ascii_lowercase();
    // Positions where the whole needle still fits.
    let Some(limit) = haystack.len().checked_sub(rest.len()) else {
        return false;
    };
    haystack[..limit].iter().enumerate().any(|(at, byte)| {
        byte.to_ascii_lowercase() == first
            && haystack[at + 1..at + 1 + rest.len()].eq_ignore_ascii_case(rest)
    })
}

fn equals(actual: Val<'_>, expected: &Literal) -> bool {
    match (actual, expected) {
        (Val::Text(a), Literal::Str(b)) => a == b.as_str(),
        (Val::Bool(a), Literal::Bool(b)) => a == *b,
        // CloudTrail writes some booleans as strings.
        (Val::Text(a), Literal::Bool(b)) => a.parse::<bool>().ok() == Some(*b),
        (Val::Json(Value::Number(a)), Literal::Num(b)) => a.as_f64() == Some(*b),
        (Val::Json(Value::Number(a)), Literal::Str(b)) => a.to_string() == *b,
        _ => false,
    }
}

/// Numeric comparison. A non-numeric field or literal does not match; it is a
/// rule bug rather than an event problem, so no error is surfaced.
fn compare(actual: Val<'_>, condition: &FieldCondition) -> bool {
    let Literal::Num(expected) = condition.value else {
        return false;
    };
    let Some(value) = actual.number() else {
        return false;
    };
    match condition.op {
        Op::Gt => value > expected,
        Op::Ge => value >= expected,
        Op::Lt => value < expected,
        Op::Le => value <= expected,
        _ => false,
    }
}

/// Maps a rule field name to the event. Dotted paths address the JSON columns
/// (`request.*`, `response.*`, `resources`, `raw`).
fn resolve<'v>(field: &str, view: &'v EventView<'v>) -> Option<Val<'v>> {
    let event = view.event;
    let text = |value: &'v Option<String>| value.as_deref().map(Val::Text);

    if let Some((column, path)) = field.split_once('.') {
        let parsed = view.json(column)?;
        return path
            .split('.')
            .try_fold(parsed, |current, key| current.get(key))
            .filter(|value| !value.is_null())
            .map(Val::json);
    }

    match field {
        "event_time" => view.time().map(Val::Text),
        "event_source" => text(&event.event_source),
        "event_name" => text(&event.event_name),
        "aws_region" => text(&event.aws_region),
        "account_id" => text(&event.account_id),
        "source_ip" => text(&event.source_ip),
        "user_agent" => text(&event.user_agent),
        "identity_type" => text(&event.identity_type),
        "identity_arn" => text(&event.identity_arn),
        "identity_name" => text(&event.identity_name),
        "mfa_authenticated" => event.mfa_authenticated.map(Val::Bool),
        "error_code" => text(&event.error_code),
        "error_message" => text(&event.error_message),
        "read_only" => event.read_only.map(Val::Bool),
        "management_event" => event.management_event.map(Val::Bool),
        "request" => text(&event.request),
        "response" => text(&event.response),
        "resources" => text(&event.resources),
        "raw" => text(&event.raw),
        _ => None,
    }
}
