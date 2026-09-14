//! Renders a parsed rule as a sentence.
//!
//! The editor shows this next to the source so the author can confirm what the
//! rule actually says. It reads the parsed AST, not the text: a description
//! derived from the source would agree with a rule the engine never saw.

use std::collections::BTreeMap;

use super::{Condition, FieldCondition, Literal, Op, Rule};
use crate::mapping::Field;

/// One line describing what the rule matches.
pub fn explain(rule: &Rule) -> String {
    let by_var: BTreeMap<&str, &FieldCondition> =
        rule.fields.iter().map(|f| (f.var.as_str(), f)).collect();
    render(&rule.condition, &by_var)
}

fn render(condition: &Condition, by_var: &BTreeMap<&str, &FieldCondition>) -> String {
    match condition {
        // A condition naming a variable the rule never defined is shown as
        // written; silently dropping it would hide the mistake.
        Condition::Var(var) => by_var
            .get(var.as_str())
            .map_or_else(|| format!("${var}"), |f| field(f)),
        Condition::Not(inner) => format!("다음이 아님 ({})", render(inner, by_var)),
        Condition::And(a, b) => format!(
            "{} 그리고 {}",
            wrap(a, by_var, false),
            wrap(b, by_var, false)
        ),
        Condition::Or(a, b) => {
            format!("{} 또는 {}", wrap(a, by_var, true), wrap(b, by_var, true))
        }
        Condition::NOf(n, vars) => {
            let parts: Vec<String> = vars
                .iter()
                .map(|var| {
                    by_var
                        .get(var.as_str())
                        .map_or_else(|| format!("${var}"), |f| field(f))
                })
                .collect();
            format!("다음 중 {n}개: {}", parts.join(", "))
        }
    }
}

/// Parenthesizes a nested group whose connective differs from its parent's,
/// because dropping those parentheses changes the meaning.
fn wrap(condition: &Condition, by_var: &BTreeMap<&str, &FieldCondition>, in_or: bool) -> String {
    let needs = match condition {
        Condition::Or(..) => !in_or,
        Condition::And(..) => in_or,
        _ => false,
    };
    let text = render(condition, by_var);
    if needs {
        format!("({text})")
    } else {
        text
    }
}

/// Predicates rather than symbols: the panel exists so the author can read
/// the rule as a sentence, and `==` is the syntax they are checking against.
///
/// Every form goes through the noun `값` so no phrasing depends on whether a
/// field name ends in a consonant — Korean subject particles (이/가) differ,
/// and picking the wrong one reads as broken text.
fn field(condition: &FieldCondition) -> String {
    let name = field_name(&condition.field);
    let value = literal(&condition.value);
    match condition.op {
        Op::Exists => format!("{name} 있음"),
        Op::Missing => format!("{name} 없음"),
        Op::In => format!("{name} 값이 다음 중 하나: {value}"),
        Op::Contains => format!("{name} 값에 {value} 포함"),
        Op::IContains => format!("{name} 값에 {value} 포함(대소문자 무시)"),
        Op::StartsWith => format!("{name} 값이 {value}로 시작"),
        Op::IStartsWith => format!("{name} 값이 {value}로 시작(대소문자 무시)"),
        Op::EndsWith => format!("{name} 값이 {value}로 끝남"),
        Op::IEndsWith => format!("{name} 값이 {value}로 끝남(대소문자 무시)"),
        Op::Matches => format!("{name} 값이 정규식 {value} 일치"),
        Op::Eq => format!("{name} 값이 {value}"),
        Op::Ne => format!("{name} 값이 {value} 아님"),
        Op::Gt => format!("{name} 값이 {value} 초과"),
        Op::Ge => format!("{name} 값이 {value} 이상"),
        Op::Lt => format!("{name} 값이 {value} 미만"),
        Op::Le => format!("{name} 값이 {value} 이하"),
    }
}

/// Column names come from the mapping so the rule, the results table and the
/// detail view all call a field the same thing. Dotted paths into
/// `request`/`response` are shown verbatim.
fn field_name(field: &str) -> String {
    Field::from_key(field).map_or_else(|| field.to_owned(), |f| f.label().to_owned())
}

fn literal(value: &Literal) -> String {
    match value {
        Literal::Str(s) => format!("\"{s}\""),
        Literal::Num(n) => {
            if n.fract() == 0.0 {
                format!("{n:.0}")
            } else {
                n.to_string()
            }
        }
        Literal::Bool(b) => b.to_string(),
        Literal::Regex(re) => format!("/{}/", re.as_str()),
        Literal::Set(items) => items
            .iter()
            .map(|item| format!("\"{item}\""))
            .collect::<Vec<_>>()
            .join(", "),
        Literal::None => String::new(),
    }
}
