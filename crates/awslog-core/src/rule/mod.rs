//! YARA-shaped rules: field mappings plus a boolean condition
//! (docs/04-rule-format.md).
//!
//! The grammar is small (one nesting level, ten operators), so it is parsed by
//! a hand-written tokenizer and recursive-descent parser instead of pulling in
//! a parser-combinator dependency.

pub(crate) mod eval;
mod explain;
mod lex;
mod parser;
mod set;

use std::collections::BTreeMap;

pub use eval::{evaluate, evaluate_any, evaluate_view, EventView, Match};
pub use explain::explain;
pub use parser::{parse_rules, rule_sources, ParseRuleError};
pub use set::{
    match_events, stream_matches, Hit, MatchReport, MatchStreamer, MatchSummary, RuleError,
    RuleMatchGroup, RuleSet, RuleSummary,
};

/// Comparison operators (docs/04 "연산자").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Contains,
    IContains,
    StartsWith,
    IStartsWith,
    EndsWith,
    IEndsWith,
    Matches,
    In,
    Gt,
    Ge,
    Lt,
    Le,
    Exists,
    Missing,
}

impl Op {
    /// True when the operator ignores ASCII case.
    fn case_insensitive(self) -> bool {
        matches!(self, Op::IContains | Op::IStartsWith | Op::IEndsWith)
    }
}

/// Right-hand side of a field condition.
#[derive(Debug, Clone)]
pub enum Literal {
    Str(String),
    Num(f64),
    Bool(bool),
    /// `in ("a", "b")`
    Set(Vec<String>),
    /// `matches /re/`, compiled once at parse time — never per event.
    Regex(Box<regex::Regex>),
    /// `exists` / `missing` take no value.
    None,
}

impl Literal {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Literal::Str(s) => Some(s),
            Literal::Regex(re) => Some(re.as_str()),
            _ => None,
        }
    }
}

/// `$var = <field> <op> <value>`
#[derive(Debug, Clone)]
pub struct FieldCondition {
    pub var: String,
    /// Normalized field name, or a dotted path into `request`/`response`.
    pub field: String,
    pub op: Op,
    pub value: Literal,
}

/// Boolean combination of field conditions.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Var(String),
    Not(Box<Condition>),
    And(Box<Condition>, Box<Condition>),
    Or(Box<Condition>, Box<Condition>),
    /// `N of ($a, $b, ...)`
    NOf(usize, Vec<String>),
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub meta: BTreeMap<String, String>,
    pub fields: Vec<FieldCondition>,
    pub condition: Condition,
}

impl Rule {
    pub fn severity(&self) -> &str {
        self.meta.get("severity").map_or("unknown", String::as_str)
    }

    pub fn description(&self) -> &str {
        self.meta.get("description").map_or("", String::as_str)
    }

    /// `meta: log_type` restricts a rule to one log type; absent means any.
    pub fn applies_to(&self, log_type: &str) -> bool {
        self.meta
            .get("log_type")
            .is_none_or(|wanted| wanted == log_type)
    }

    /// The stored columns this rule reads: a field's first path segment
    /// (`response.ConsoleLogin` → `response`). Lets the evaluation scan
    /// select only what the rule can look at.
    pub fn columns(&self) -> std::collections::BTreeSet<&str> {
        self.fields
            .iter()
            .map(|f| f.field.split(['.', '[']).next().unwrap_or(&f.field))
            .collect()
    }
}
