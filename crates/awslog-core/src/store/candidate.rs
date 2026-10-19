//! Necessary conditions of rules as SQL (docs/05 "룰 평가 패스의 읽기 전략").
//!
//! A candidate filter lets DuckDB drop the rows a rule set cannot match
//! before they are shipped to the evaluator. Rows that pass are still
//! evaluated in full, so a filter may be weaker than its rule but never
//! stronger: one dropped row the rule would have matched is a wrong answer,
//! not a slow one. Each predicate here follows from `rule::eval` (`resolve`,
//! `check`, `equals`, `substring`).

use duckdb::types::Value;

use crate::detect::LogType;
use crate::rule::{Condition, FieldCondition, Literal, Op, Rule};

/// A necessary condition for a rule set: every event the set can match
/// satisfies it, so the scan may skip the rest.
pub(super) struct Candidate {
    /// Ready to append to the scan's `WHERE`, leading ` AND` included.
    pub(super) sql: String,
    pub(super) params: Vec<Value>,
}

/// A rule set's filters, one per kind of stored `raw`: the parsers render
/// `raw` with serde_json for some log types and keep the producer's own
/// line for others, and only the rendered kind can be searched as text.
#[derive(Default)]
pub(super) struct Candidates {
    verbatim: Option<Candidate>,
    rendered: Option<Candidate>,
}

impl Candidates {
    /// The filters for a whole set. An event matches the set when it
    /// matches one of its rules, so the rules' filters are OR-ed, and one
    /// rule without a filter leaves the whole set unfiltered.
    pub(super) fn for_rules(rules: &[&Rule]) -> Self {
        let build = |rendered_raw: bool| {
            let (sql, params) = rules
                .iter()
                .map(|rule| holds(&rule.condition, rule, rendered_raw))
                .reduce(any)??;
            Some(Candidate {
                sql: format!(" AND ({sql})"),
                params,
            })
        };
        Self {
            verbatim: build(false),
            rendered: build(true),
        }
    }

    pub(super) fn get(&self, rendered_raw: bool) -> Option<&Candidate> {
        if rendered_raw {
            self.rendered.as_ref()
        } else {
            self.verbatim.as_ref()
        }
    }

    /// Whether the two kinds filter differently, i.e. whether a scan has to
    /// tell their files apart.
    pub(super) fn split(&self) -> bool {
        self.verbatim.as_ref().map(|c| &c.sql) != self.rendered.as_ref().map(|c| &c.sql)
    }
}

/// Log types whose `raw` the parser renders with serde_json
/// (`parse::normalize`, `parse::normalize_alb`). The NDJSON producers keep
/// their original line, where a value may be escaped any way JSON allows.
pub(super) fn renders_raw(log_type: &str) -> bool {
    [LogType::CloudTrail, LogType::Unknown, LogType::AlbAccess]
        .iter()
        .any(|kind| kind.as_str() == log_type)
}

/// SQL holding for every row the condition holds for. `None` is "no known
/// restriction", i.e. `true`.
type Pred = Option<(String, Vec<Value>)>;

/// Text columns the evaluator reads back as plain strings, so SQL and the
/// evaluator compare them byte for byte.
pub(super) const TEXT_COLUMNS: [&str; 11] = [
    "event_source",
    "event_name",
    "aws_region",
    "account_id",
    "source_ip",
    "user_agent",
    "identity_type",
    "identity_arn",
    "identity_name",
    "error_code",
    "error_message",
];
pub(super) const FLAG_COLUMNS: [&str; 3] = ["mfa_authenticated", "read_only", "management_event"];
const JSON_COLUMNS: [&str; 4] = ["request", "response", "resources", "raw"];

fn sql(text: String, params: Vec<Value>) -> Pred {
    Some((text, params))
}

fn never() -> Pred {
    sql("false".to_owned(), Vec::new())
}

fn all(a: Pred, b: Pred) -> Pred {
    match (a, b) {
        (Some((a, mut params)), Some((b, more))) => {
            params.extend(more);
            sql(format!("({a} AND {b})"), params)
        }
        (one, None) | (None, one) => one,
    }
}

fn any(a: Pred, b: Pred) -> Pred {
    match (a, b) {
        (Some((a, mut params)), Some((b, more))) => {
            params.extend(more);
            sql(format!("({a} OR {b})"), params)
        }
        _ => None,
    }
}

/// What every row `condition` holds for satisfies. `rendered_raw`: the
/// rows' `raw` was rendered by serde_json ([`renders_raw`]).
fn holds(condition: &Condition, rule: &Rule, rendered_raw: bool) -> Pred {
    let variable = |var: &str| variable(rule, var, rendered_raw);
    match condition {
        Condition::Var(var) => variable(var),
        Condition::And(a, b) => all(holds(a, rule, rendered_raw), holds(b, rule, rendered_raw)),
        Condition::Or(a, b) => any(holds(a, rule, rendered_raw), holds(b, rule, rendered_raw)),
        // The rows `not` keeps are the ones its operand rejects; a filter
        // for the operand says nothing about them.
        Condition::Not(_) => None,
        Condition::NOf(0, _) => None,
        Condition::NOf(count, vars) if *count > vars.len() => never(),
        Condition::NOf(count, vars) if *count == vars.len() => {
            vars.iter().map(|var| variable(var)).fold(None, all)
        }
        // At least one of the listed variables has to hold.
        Condition::NOf(_, vars) => vars.iter().map(|var| variable(var)).reduce(any).flatten(),
    }
}

/// A variable holds when any field condition bound to it does.
fn variable(rule: &Rule, var: &str, rendered_raw: bool) -> Pred {
    rule.fields
        .iter()
        .filter(|field| field.var == var)
        .map(|condition| field(condition, rendered_raw))
        .reduce(any)
        .unwrap_or_else(never)
}

fn field(field: &FieldCondition, rendered_raw: bool) -> Pred {
    let (column, path) = match field.field.split_once('.') {
        Some((column, path)) => (column, Some(path)),
        None => (field.field.as_str(), None),
    };
    let json = JSON_COLUMNS.contains(&column);
    let known = match path {
        Some(_) => json,
        None => {
            json || column == "event_time"
                || TEXT_COLUMNS.contains(&column)
                || FLAG_COLUMNS.contains(&column)
        }
    };
    // `resolve` finds nothing for such a field, and only `missing` holds on
    // nothing.
    if !known {
        return if field.op == Op::Missing {
            None
        } else {
            never()
        };
    }
    if field.op == Op::Missing {
        // A whole column is missing exactly when it is NULL; a path can be
        // missing inside a body that is there.
        return match path {
            None => sql(format!("{column} IS NULL"), Vec::new()),
            Some(_) => None,
        };
    }
    // Every other operator needs a value, and a NULL column holds none.
    let present = sql(format!("{column} IS NOT NULL"), Vec::new());
    let value = match path {
        None if json => text(&format!("CAST({column} AS VARCHAR)"), field),
        None if TEXT_COLUMNS.contains(&column) => text(column, field),
        None if FLAG_COLUMNS.contains(&column) => flag(column, field),
        // `event_time` is compared as formatted text the table does not hold.
        None => None,
        Some(_) if column == "raw" && !rendered_raw => None,
        Some(path) => json_value(column, path, field),
    };
    all(present, value)
}

/// A string the evaluator compares as stored: a text column, or a JSON
/// body read whole.
fn text(expr: &str, field: &FieldCondition) -> Pred {
    let one = |template: String, value: &str| sql(template, vec![Value::Text(value.to_owned())]);
    match (field.op, &field.value) {
        (Op::Eq, Literal::Str(value)) => one(format!("{expr} = ?"), value),
        // `equals` reads exactly "true"/"false" as a boolean.
        (Op::Eq, Literal::Bool(value)) => one(format!("{expr} = ?"), &value.to_string()),
        // An empty set matches nothing; `IN ()` is not SQL, so leave it.
        (Op::In, Literal::Set(items)) if !items.is_empty() => sql(
            format!("{expr} IN ({})", vec!["?"; items.len()].join(", ")),
            items.iter().cloned().map(Value::Text).collect(),
        ),
        (Op::Contains, Literal::Str(needle)) => one(format!("contains({expr}, ?)"), needle),
        (Op::StartsWith, Literal::Str(needle)) => one(format!("starts_with({expr}, ?)"), needle),
        (Op::EndsWith, Literal::Str(needle)) => one(format!("suffix({expr}, ?)"), needle),
        // The `i` operators fold ASCII only. An all-ASCII needle matches
        // only ASCII bytes, which `lower` folds the same way; what `lower`
        // does to other characters can only add matches.
        (Op::IContains | Op::IStartsWith | Op::IEndsWith, Literal::Str(needle))
            if needle.is_ascii() =>
        {
            let function = match field.op {
                Op::IContains => "contains",
                Op::IStartsWith => "starts_with",
                _ => "suffix",
            };
            one(
                format!("{function}(lower({expr}), ?)"),
                &needle.to_ascii_lowercase(),
            )
        }
        _ => None,
    }
}

fn flag(column: &str, field: &FieldCondition) -> Pred {
    match (field.op, &field.value) {
        (Op::Eq, Literal::Bool(value)) => {
            sql(format!("{column} = ?"), vec![Value::Boolean(*value)])
        }
        _ => None,
    }
}

/// A value at a path inside a body the parser serialized with serde_json
/// (`request`/`response`/`resources`, and `raw` where [`renders_raw`]).
/// That text is compact, escapes only `"`, `\` and control characters, has
/// no duplicate keys, and renders every string, number and literal of a
/// parsed value exactly as the evaluator re-renders it. So a value the
/// evaluator accepts leaves fragments the body must contain; where, and
/// under which key, is left to the evaluator.
fn json_value(column: &str, path: &str, field: &FieldCondition) -> Pred {
    let expr = format!("CAST({column} AS VARCHAR)");
    match (field.op, &field.value) {
        (Op::Gt | Op::Ge | Op::Lt | Op::Le | Op::Eq, Literal::Num(bound)) => {
            numeric(column, path, field.op, *bound)
        }
        (Op::Eq, Literal::Str(value)) => contains(&expr, &[rendered(value)], false),
        (Op::Eq, Literal::Bool(value)) => contains(&expr, &[value.to_string()], false),
        // `in` compares the value's text, and an object's or array's text
        // is a re-rendering whose key order the body need not share.
        (Op::In, Literal::Set(items))
            if !items.is_empty() && !items.iter().any(|item| item.starts_with(['{', '['])) =>
        {
            items
                .iter()
                .map(|item| contains(&expr, &[rendered(item)], false))
                .reduce(any)
                .flatten()
        }
        (Op::Contains | Op::StartsWith | Op::EndsWith, Literal::Str(needle)) => {
            contains(&expr, &pieces(needle), false)
        }
        (Op::IContains | Op::IStartsWith | Op::IEndsWith, Literal::Str(needle))
            if needle.is_ascii() =>
        {
            contains(&expr, &pieces(needle), true)
        }
        _ => None,
    }
}

/// `number()` takes a JSON number as `as_f64` reads it, and parses a string
/// its own way; `equals` against a number literal takes only JSON numbers.
/// DuckDB reads the number's text into the same double, so numbers are
/// decided here and strings are left to the evaluator. A missing path,
/// `null`, a boolean, an object or an array yields no number at all.
fn numeric(column: &str, path: &str, op: Op, bound: f64) -> Pred {
    let path = json_path(path)?;
    let symbol = match op {
        Op::Gt => ">",
        Op::Ge => ">=",
        Op::Lt => "<",
        Op::Le => "<=",
        _ => "=",
    };
    let number = format!("TRY_CAST(json_extract_string({column}, '{path}') AS DOUBLE) {symbol} ?");
    let text = if op == Op::Eq {
        number
    } else {
        format!("(json_type({column}, '{path}') = 'VARCHAR' OR {number})")
    };
    sql(text, vec![Value::Double(bound)])
}

/// The JSONPath of an evaluator path, each segment an object key as
/// `Value::get` takes it. Only plain key spellings are inlined into SQL.
fn json_path(path: &str) -> Option<String> {
    let mut out = String::from("$");
    for key in path.split('.') {
        let plain = !key.is_empty()
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !plain {
            return None;
        }
        out.push_str(&format!(".\"{key}\""));
    }
    Some(out)
}

/// How a value whose text equals `value` appears in a body: bare when it
/// could be a number or a boolean (`500`, `true`), otherwise as a quoted
/// JSON string. A bare fragment also covers the quoted spelling.
fn rendered(value: &str) -> String {
    let bare = value == "true"
        || value == "false"
        || (!value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b)));
    if bare {
        value.to_owned()
    } else {
        serde_json::to_string(value).unwrap_or_default()
    }
}

/// The parts of a substring needle a body must hold verbatim. Across JSON
/// structure (`{}[]:,`), quotes, escapes or control characters a match may
/// straddle tokens or an escape the body spells differently; between them
/// it cannot.
fn pieces(needle: &str) -> Vec<String> {
    needle
        .split(|c: char| "{}[]:,\"\\".contains(c) || c.is_control())
        .filter(|piece| !piece.is_empty())
        .map(str::to_owned)
        .collect()
}

fn contains(expr: &str, fragments: &[String], fold: bool) -> Pred {
    let haystack = if fold {
        format!("lower({expr})")
    } else {
        expr.to_owned()
    };
    fragments
        .iter()
        .map(|fragment| {
            let fragment = if fold {
                fragment.to_ascii_lowercase()
            } else {
                fragment.clone()
            };
            sql(
                format!("contains({haystack}, ?)"),
                vec![Value::Text(fragment)],
            )
        })
        .fold(None, all)
}
