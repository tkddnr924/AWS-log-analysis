//! Recursive-descent parser over the token stream.

use std::collections::{BTreeMap, BTreeSet};

use super::lex::{tokenize, tokenize_spanned, LexError, Token};
use super::{Condition, FieldCondition, Literal, Op, Rule};

#[derive(Debug, thiserror::Error)]
pub enum ParseRuleError {
    #[error("rule syntax error: {0}")]
    Lex(#[from] LexError),
    #[error("rule `{rule}`: {message}")]
    Syntax { rule: String, message: String },
    #[error("duplicate rule id `{id}`")]
    DuplicateId { id: String },
    #[error("rule `{rule}`: condition uses undefined variable `{var}`")]
    UndefinedVar { rule: String, var: String },
    #[error("rule `{rule}`: unsupported operator `{op}`")]
    UnsupportedOp { rule: String, op: String },
}

/// Parses every rule in one source file.
pub fn parse_rules(src: &str) -> Result<Vec<Rule>, ParseRuleError> {
    let tokens = tokenize(src)?;
    let mut parser = Parser { tokens, pos: 0 };
    let mut rules = Vec::new();
    let mut seen = BTreeSet::new();

    while parser.peek().is_some() {
        let rule = parser.rule()?;
        if !seen.insert(rule.id.clone()) {
            return Err(ParseRuleError::DuplicateId { id: rule.id });
        }
        rules.push(rule);
    }

    Ok(rules)
}

/// The original text of every rule in `src`, keyed by id, so an editor can
/// open one rule out of a multi-rule file. Token-level only: call
/// [`parse_rules`] first when the source must also be valid.
pub fn rule_sources(src: &str) -> Result<Vec<(String, String)>, ParseRuleError> {
    let tokens = tokenize_spanned(src)?;
    let mut sources = Vec::new();
    let mut depth = 0usize;
    let mut open: Option<(String, usize)> = None;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i].0 {
            Token::Word(word) if word == "rule" && depth == 0 => {
                if let Some((Token::Word(id), _)) = tokens.get(i + 1) {
                    open = Some((id.clone(), tokens[i].1.start));
                }
            }
            Token::LBrace => depth += 1,
            Token::RBrace => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some((id, start)) = open.take() {
                        sources.push((id, src[start..tokens[i].1.end].to_owned()));
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    Ok(sources)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn eat(&mut self, expected: &Token, rule: &str) -> Result<(), ParseRuleError> {
        if self.peek() == Some(expected) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ParseRuleError::Syntax {
                rule: rule.to_string(),
                message: format!("expected {expected:?}, found {:?}", self.peek()),
            })
        }
    }

    fn rule(&mut self) -> Result<Rule, ParseRuleError> {
        match self.next() {
            Some(Token::Word(word)) if word == "rule" => {}
            other => {
                return Err(ParseRuleError::Syntax {
                    rule: "<top level>".into(),
                    message: format!("expected `rule`, found {other:?}"),
                })
            }
        }

        let id = match self.next() {
            Some(Token::Word(id)) => id,
            other => {
                return Err(ParseRuleError::Syntax {
                    rule: "<top level>".into(),
                    message: format!("expected rule identifier, found {other:?}"),
                })
            }
        };

        self.eat(&Token::LBrace, &id)?;

        let mut meta = BTreeMap::new();
        let mut fields = Vec::new();
        let mut condition = None;

        while self.peek() != Some(&Token::RBrace) {
            let section = match self.next() {
                Some(Token::Word(word)) => word,
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: id.clone(),
                        message: format!("expected a section name, found {other:?}"),
                    })
                }
            };
            self.eat(&Token::Colon, &id)?;

            match section.as_str() {
                "meta" => meta = self.meta_section(&id)?,
                "fields" => fields = self.fields_section(&id)?,
                "condition" => condition = Some(self.condition(&id)?),
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: id.clone(),
                        message: format!("unknown section `{other}`"),
                    })
                }
            }
        }
        self.eat(&Token::RBrace, &id)?;

        let condition = condition.ok_or_else(|| ParseRuleError::Syntax {
            rule: id.clone(),
            message: "missing `condition:` section".into(),
        })?;

        // Every referenced variable must be declared, or the rule silently
        // never matches.
        let declared: BTreeSet<&str> = fields.iter().map(|f| f.var.as_str()).collect();
        check_vars(&condition, &declared, &id)?;

        Ok(Rule {
            id,
            meta,
            fields,
            condition,
        })
    }

    fn meta_section(&mut self, rule: &str) -> Result<BTreeMap<String, String>, ParseRuleError> {
        let mut meta = BTreeMap::new();
        while let Some(Token::Word(_)) = self.peek() {
            // A section name is followed by `:`; a meta key by `=`.
            if self.tokens.get(self.pos + 1) != Some(&Token::Sym("=")) {
                break;
            }
            let Some(Token::Word(key)) = self.next() else {
                unreachable!("peeked a word")
            };
            self.eat(&Token::Sym("="), rule)?;
            match self.next() {
                Some(Token::Str(value)) => {
                    meta.insert(key, value);
                }
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("meta `{key}` needs a string value, found {other:?}"),
                    })
                }
            }
        }
        Ok(meta)
    }

    fn fields_section(&mut self, rule: &str) -> Result<Vec<FieldCondition>, ParseRuleError> {
        let mut fields = Vec::new();
        while let Some(Token::Var(_)) = self.peek() {
            let Some(Token::Var(var)) = self.next() else {
                unreachable!("peeked a var")
            };
            self.eat(&Token::Sym("="), rule)?;

            let field = match self.next() {
                Some(Token::Word(field)) => field,
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("expected a field name, found {other:?}"),
                    })
                }
            };

            let (op, value) = self.operator(rule)?;
            fields.push(FieldCondition {
                var,
                field,
                op,
                value,
            });
        }
        Ok(fields)
    }

    fn operator(&mut self, rule: &str) -> Result<(Op, Literal), ParseRuleError> {
        let token = self.next();
        let op = match &token {
            Some(Token::Sym("==")) => Op::Eq,
            Some(Token::Sym("!=")) => Op::Ne,
            Some(Token::Sym(">")) => Op::Gt,
            Some(Token::Sym(">=")) => Op::Ge,
            Some(Token::Sym("<")) => Op::Lt,
            Some(Token::Sym("<=")) => Op::Le,
            Some(Token::Word(word)) => match word.as_str() {
                "contains" => Op::Contains,
                "icontains" => Op::IContains,
                "startswith" => Op::StartsWith,
                "istartswith" => Op::IStartsWith,
                "endswith" => Op::EndsWith,
                "iendswith" => Op::IEndsWith,
                "matches" => Op::Matches,
                "in" => Op::In,
                "exists" => return Ok((Op::Exists, Literal::None)),
                "missing" => return Ok((Op::Missing, Literal::None)),
                other => {
                    return Err(ParseRuleError::UnsupportedOp {
                        rule: rule.to_string(),
                        op: other.to_string(),
                    })
                }
            },
            other => {
                return Err(ParseRuleError::UnsupportedOp {
                    rule: rule.to_string(),
                    op: format!("{other:?}"),
                })
            }
        };

        let value = match op {
            Op::In => self.value_set(rule)?,
            Op::Matches => match self.next() {
                Some(Token::Regex(pattern)) => {
                    // Compiled here so evaluation never pays for it, and a bad
                    // pattern fails loading instead of silently never matching.
                    let compiled =
                        regex::Regex::new(&pattern).map_err(|e| ParseRuleError::Syntax {
                            rule: rule.to_string(),
                            message: format!("invalid regex `/{pattern}/`: {e}"),
                        })?;
                    Literal::Regex(Box::new(compiled))
                }
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("`matches` needs /regex/, found {other:?}"),
                    })
                }
            },
            _ => match self.next() {
                Some(Token::Str(text)) => Literal::Str(text),
                Some(Token::Num(number)) => Literal::Num(number),
                Some(Token::Word(word)) if word == "true" => Literal::Bool(true),
                Some(Token::Word(word)) if word == "false" => Literal::Bool(false),
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("expected a value, found {other:?}"),
                    })
                }
            },
        };

        Ok((op, value))
    }

    fn value_set(&mut self, rule: &str) -> Result<Literal, ParseRuleError> {
        self.eat(&Token::LParen, rule)?;
        let mut items = Vec::new();
        loop {
            match self.next() {
                Some(Token::Str(text)) => items.push(text),
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("`in` takes string values, found {other:?}"),
                    })
                }
            }
            match self.next() {
                Some(Token::Comma) => {}
                Some(Token::RParen) => break,
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("expected `,` or `)`, found {other:?}"),
                    })
                }
            }
        }
        Ok(Literal::Set(items))
    }

    /// `or` binds loosest, then `and`, then `not`.
    fn condition(&mut self, rule: &str) -> Result<Condition, ParseRuleError> {
        let mut left = self.condition_and(rule)?;
        while let Some(Token::Word(word)) = self.peek() {
            if word != "or" {
                break;
            }
            self.pos += 1;
            let right = self.condition_and(rule)?;
            left = Condition::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn condition_and(&mut self, rule: &str) -> Result<Condition, ParseRuleError> {
        let mut left = self.condition_unary(rule)?;
        while let Some(Token::Word(word)) = self.peek() {
            if word != "and" {
                break;
            }
            self.pos += 1;
            let right = self.condition_unary(rule)?;
            left = Condition::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn condition_unary(&mut self, rule: &str) -> Result<Condition, ParseRuleError> {
        match self.peek() {
            Some(Token::Word(word)) if word == "not" => {
                self.pos += 1;
                Ok(Condition::Not(Box::new(self.condition_unary(rule)?)))
            }
            Some(Token::LParen) => {
                self.pos += 1;
                let inner = self.condition(rule)?;
                self.eat(&Token::RParen, rule)?;
                Ok(inner)
            }
            Some(Token::Var(_)) => {
                let Some(Token::Var(var)) = self.next() else {
                    unreachable!("peeked a var")
                };
                Ok(Condition::Var(var))
            }
            Some(Token::Num(_)) => self.n_of(rule),
            other => Err(ParseRuleError::Syntax {
                rule: rule.to_string(),
                message: format!("expected a condition, found {other:?}"),
            }),
        }
    }

    /// `N of ($a, $b, ...)`
    fn n_of(&mut self, rule: &str) -> Result<Condition, ParseRuleError> {
        let Some(Token::Num(count)) = self.next() else {
            unreachable!("peeked a number")
        };
        match self.next() {
            Some(Token::Word(word)) if word == "of" => {}
            other => {
                return Err(ParseRuleError::Syntax {
                    rule: rule.to_string(),
                    message: format!("expected `of` after a count, found {other:?}"),
                })
            }
        }
        self.eat(&Token::LParen, rule)?;

        let mut vars = Vec::new();
        loop {
            match self.next() {
                Some(Token::Var(var)) => vars.push(var),
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("`of` takes variables, found {other:?}"),
                    })
                }
            }
            match self.next() {
                Some(Token::Comma) => {}
                Some(Token::RParen) => break,
                other => {
                    return Err(ParseRuleError::Syntax {
                        rule: rule.to_string(),
                        message: format!("expected `,` or `)`, found {other:?}"),
                    })
                }
            }
        }

        Ok(Condition::NOf(count as usize, vars))
    }
}

fn check_vars(
    condition: &Condition,
    declared: &BTreeSet<&str>,
    rule: &str,
) -> Result<(), ParseRuleError> {
    let undefined = |var: &String| {
        (!declared.contains(var.as_str())).then(|| ParseRuleError::UndefinedVar {
            rule: rule.to_string(),
            var: var.clone(),
        })
    };

    match condition {
        Condition::Var(var) => match undefined(var) {
            Some(err) => Err(err),
            None => Ok(()),
        },
        Condition::Not(inner) => check_vars(inner, declared, rule),
        Condition::And(a, b) | Condition::Or(a, b) => {
            check_vars(a, declared, rule)?;
            check_vars(b, declared, rule)
        }
        Condition::NOf(_, vars) => {
            for var in vars {
                if let Some(err) = undefined(var) {
                    return Err(err);
                }
            }
            Ok(())
        }
    }
}
