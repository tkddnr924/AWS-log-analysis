//! Tokenizer for the rule grammar. Comments are stripped here so the parser
//! never sees them.

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Bare word: keyword, field name or operator name.
    Word(String),
    /// `$name`
    Var(String),
    Str(String),
    Num(f64),
    /// `/pattern/`
    Regex(String),
    LBrace,
    RBrace,
    LParen,
    RParen,
    Comma,
    Colon,
    /// `==`, `!=`, `>`, `>=`, `<`, `<=`, `=`
    Sym(&'static str),
}

#[derive(Debug, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct LexError {
    pub line: usize,
    pub message: String,
}

/// Splits source into tokens, dropping `//` and `/* */` comments.
pub fn tokenize(src: &str) -> Result<Vec<Token>, LexError> {
    Ok(tokenize_spanned(src)?
        .into_iter()
        .map(|(token, _)| token)
        .collect())
}

/// [`tokenize`] with each token's byte range in `src`, so a rule's original
/// text can be cut out of a multi-rule file.
pub fn tokenize_spanned(src: &str) -> Result<Vec<(Token, std::ops::Range<usize>)>, LexError> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let mut spans = Vec::new();
    let mut i = 0;
    let mut line = 1;

    while i < bytes.len() {
        let b = bytes[i];
        let start = i;
        let before = tokens.len();

        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Comments. `/` also starts a regex, so decide by the next byte.
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    line += 1;
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }

        match b {
            b'{' => push(&mut tokens, Token::LBrace, &mut i),
            b'}' => push(&mut tokens, Token::RBrace, &mut i),
            b'(' => push(&mut tokens, Token::LParen, &mut i),
            b')' => push(&mut tokens, Token::RParen, &mut i),
            b',' => push(&mut tokens, Token::Comma, &mut i),
            b':' => push(&mut tokens, Token::Colon, &mut i),
            b'"' => {
                let (text, next) = read_string(src, i, line)?;
                tokens.push(Token::Str(text));
                i = next;
            }
            b'/' => {
                let (pattern, next) = read_regex(src, i, line)?;
                tokens.push(Token::Regex(pattern));
                i = next;
            }
            b'=' | b'!' | b'>' | b'<' => {
                let two = &src[i..(i + 2).min(src.len())];
                let sym = match two {
                    "==" => Some("=="),
                    "!=" => Some("!="),
                    ">=" => Some(">="),
                    "<=" => Some("<="),
                    _ => None,
                };
                if let Some(sym) = sym {
                    tokens.push(Token::Sym(sym));
                    i += 2;
                } else {
                    let one = match b {
                        b'=' => "=",
                        b'>' => ">",
                        b'<' => "<",
                        _ => {
                            return Err(LexError {
                                line,
                                message: format!("unexpected `{}`", b as char),
                            })
                        }
                    };
                    tokens.push(Token::Sym(one));
                    i += 1;
                }
            }
            b'$' => {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                tokens.push(Token::Var(src[start..i].to_string()));
            }
            _ if b.is_ascii_digit() || b == b'-' => {
                let start = i;
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                    i += 1;
                }
                let text = &src[start..i];
                let value = text.parse::<f64>().map_err(|_| LexError {
                    line,
                    message: format!("invalid number `{text}`"),
                })?;
                tokens.push(Token::Num(value));
            }
            _ if b.is_ascii_alphabetic() || b == b'_' => {
                let start = i;
                while i < bytes.len()
                    && (bytes[i].is_ascii_alphanumeric()
                        || bytes[i] == b'_'
                        || bytes[i] == b'.'
                        || bytes[i] == b'[')
                {
                    // Field paths may contain dots and `[]` for arrays.
                    if bytes[i] == b'[' {
                        while i < bytes.len() && bytes[i] != b']' {
                            i += 1;
                        }
                    }
                    i += 1;
                }
                tokens.push(Token::Word(src[start..i].to_string()));
            }
            other => {
                return Err(LexError {
                    line,
                    message: format!("unexpected `{}`", other as char),
                })
            }
        }
        if tokens.len() > before {
            spans.push(start..i);
        }
    }

    Ok(tokens.into_iter().zip(spans).collect())
}

fn push(tokens: &mut Vec<Token>, token: Token, i: &mut usize) {
    tokens.push(token);
    *i += 1;
}

/// Reads a double-quoted string with `\` escapes.
fn read_string(src: &str, start: usize, line: usize) -> Result<(String, usize), LexError> {
    let bytes = src.as_bytes();
    let mut i = start + 1;
    let mut text = String::new();

    while i < bytes.len() {
        match bytes[i] {
            b'\\' if i + 1 < bytes.len() => {
                let escaped = bytes[i + 1];
                text.push(match escaped {
                    b'n' => '\n',
                    b't' => '\t',
                    other => other as char,
                });
                i += 2;
            }
            b'"' => return Ok((text, i + 1)),
            _ => {
                // Copy whole UTF-8 characters, not bytes.
                let ch = src[i..].chars().next().expect("in bounds");
                text.push(ch);
                i += ch.len_utf8();
            }
        }
    }

    Err(LexError {
        line,
        message: "unterminated string".into(),
    })
}

/// Reads `/pattern/`, honouring `\/`.
fn read_regex(src: &str, start: usize, line: usize) -> Result<(String, usize), LexError> {
    let bytes = src.as_bytes();
    let mut i = start + 1;
    let mut text = String::new();

    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1) == Some(&b'/') => {
                text.push('/');
                i += 2;
            }
            b'/' => return Ok((text, i + 1)),
            b'\n' => break,
            _ => {
                let ch = src[i..].chars().next().expect("in bounds");
                text.push(ch);
                i += ch.len_utf8();
            }
        }
    }

    Err(LexError {
        line,
        message: "unterminated regex".into(),
    })
}
