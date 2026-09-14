//! Rule evaluation. A rule either matches with the values that fired, or does
//! not match — event data never produces an evaluation error.

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
}

impl<'a> EventView<'a> {
    pub fn new(event: &'a NormalizedEvent) -> Self {
        Self {
            event,
            request: OnceCell::new(),
            response: OnceCell::new(),
            resources: OnceCell::new(),
            raw: OnceCell::new(),
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
}

/// Evaluates one rule against one event. Prefer [`evaluate_view`] when several
/// rules run against the same event.
/// True when any rule matches. Shares one `EventView` across the set.
pub fn evaluate_any<'a>(
    rules: impl IntoIterator<Item = &'a Rule>,
    event: &NormalizedEvent,
) -> bool {
    let view = EventView::new(event);
    rules
        .into_iter()
        .any(|rule| evaluate_view(rule, &view).is_some())
}

pub fn evaluate(rule: &Rule, event: &NormalizedEvent) -> Option<Match> {
    evaluate_view(rule, &EventView::new(event))
}

/// Evaluates one rule against a cached event view.
pub fn evaluate_view(rule: &Rule, view: &EventView<'_>) -> Option<Match> {
    let mut satisfied = BTreeMap::new();

    for field in &rule.fields {
        if let Some(value) = check(field, view) {
            satisfied.insert(field.var.clone(), value);
        }
    }

    if !holds(&rule.condition, &satisfied) {
        return None;
    }

    // Report only the variables the condition could have used.
    Some(Match {
        rule_id: rule.id.clone(),
        matched_fields: satisfied,
    })
}

fn holds(condition: &Condition, satisfied: &BTreeMap<String, String>) -> bool {
    match condition {
        Condition::Var(var) => satisfied.contains_key(var),
        Condition::Not(inner) => !holds(inner, satisfied),
        Condition::And(a, b) => holds(a, satisfied) && holds(b, satisfied),
        Condition::Or(a, b) => holds(a, satisfied) || holds(b, satisfied),
        Condition::NOf(count, vars) => {
            vars.iter().filter(|v| satisfied.contains_key(*v)).count() >= *count
        }
    }
}

/// Returns the field's value when the condition holds.
fn check(condition: &FieldCondition, view: &EventView<'_>) -> Option<String> {
    let actual = resolve(&condition.field, view);

    match condition.op {
        Op::Exists => return actual.map(render),
        Op::Missing => {
            return match actual {
                None => Some(String::new()),
                Some(_) => None,
            }
        }
        _ => {}
    }

    // An absent field never satisfies a value comparison.
    let actual = actual?;
    let text = render(actual.clone());

    let satisfied = match condition.op {
        Op::Eq => equals(&actual, &condition.value),
        Op::Ne => !equals(&actual, &condition.value),
        Op::Contains | Op::IContains => with_case(&text, condition, |haystack, needle| {
            haystack.contains(needle)
        }),
        Op::StartsWith | Op::IStartsWith => with_case(&text, condition, |haystack, needle| {
            haystack.starts_with(needle)
        }),
        Op::EndsWith | Op::IEndsWith => with_case(&text, condition, |haystack, needle| {
            haystack.ends_with(needle)
        }),
        // Pre-compiled at parse time.
        Op::Matches => match &condition.value {
            Literal::Regex(re) => re.is_match(&text),
            _ => false,
        },
        Op::In => match &condition.value {
            Literal::Set(items) => items.iter().any(|item| item == &text),
            _ => false,
        },
        Op::Gt | Op::Ge | Op::Lt | Op::Le => compare(&actual, condition),
        Op::Exists | Op::Missing => unreachable!("handled above"),
    };

    satisfied.then_some(text)
}

fn with_case(text: &str, condition: &FieldCondition, test: fn(&str, &str) -> bool) -> bool {
    let Some(needle) = condition.value.as_str() else {
        return false;
    };
    if condition.op.case_insensitive() {
        test(&text.to_ascii_lowercase(), &needle.to_ascii_lowercase())
    } else {
        test(text, needle)
    }
}

fn equals(actual: &Value, expected: &Literal) -> bool {
    match (actual, expected) {
        (Value::String(a), Literal::Str(b)) => a == b,
        (Value::Bool(a), Literal::Bool(b)) => a == b,
        (Value::Number(a), Literal::Num(b)) => a.as_f64() == Some(*b),
        // CloudTrail writes some booleans as strings.
        (Value::String(a), Literal::Bool(b)) => a.parse::<bool>().ok() == Some(*b),
        (Value::Number(a), Literal::Str(b)) => a.to_string() == *b,
        _ => false,
    }
}

/// Numeric comparison. A non-numeric field or literal does not match; it is a
/// rule bug rather than an event problem, so no error is surfaced.
fn compare(actual: &Value, condition: &FieldCondition) -> bool {
    let Literal::Num(expected) = condition.value else {
        return false;
    };
    let Some(value) = numeric(actual) else {
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

fn numeric(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        // Timestamps and numeric strings still compare numerically.
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn render(value: Value) -> String {
    match value {
        Value::String(text) => text,
        other => other.to_string(),
    }
}

/// Maps a rule field name to the event. Dotted paths address the JSON columns
/// (`request.*`, `response.*`, `resources`, `raw`).
fn resolve(field: &str, view: &EventView<'_>) -> Option<Value> {
    let event = view.event;
    let text = |value: &Option<String>| value.clone().map(Value::String);

    if let Some((column, path)) = field.split_once('.') {
        let parsed = view.json(column)?;
        return path
            .split('.')
            .try_fold(parsed, |current, key| current.get(key))
            .filter(|value| !value.is_null())
            .cloned();
    }

    match field {
        "event_time" => event.event_time.map(|t| {
            Value::String(
                t.format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            )
        }),
        "event_source" => text(&event.event_source),
        "event_name" => text(&event.event_name),
        "aws_region" => text(&event.aws_region),
        "account_id" => text(&event.account_id),
        "source_ip" => text(&event.source_ip),
        "user_agent" => text(&event.user_agent),
        "identity_type" => text(&event.identity_type),
        "identity_arn" => text(&event.identity_arn),
        "identity_name" => text(&event.identity_name),
        "mfa_authenticated" => event.mfa_authenticated.map(Value::Bool),
        "error_code" => text(&event.error_code),
        "error_message" => text(&event.error_message),
        "read_only" => event.read_only.map(Value::Bool),
        "management_event" => event.management_event.map(Value::Bool),
        "request" => text(&event.request),
        "response" => text(&event.response),
        "resources" => text(&event.resources),
        "raw" => text(&event.raw),
        _ => None,
    }
}
