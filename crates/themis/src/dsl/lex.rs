//! The lexer shared by every syntax of the language. It splits a source into tokens and lifts the
//! `//` comments out of the token stream, so the syntaxes can keep them as notes.

use crate::dsl::error::{Raw, Span};
use crate::dsl::time;

/// Two-character punctuation, tried before the single characters.
const PUNCT2: [&str; 7] = ["==", "!=", "<=", ">=", "&&", "||", "->"];
/// Single-character punctuation.
const PUNCT1: &str = "{}()[],=:<>#@|&!-*";
/// Punctuation after which a `-` starts a negative number instead of an exclusion.
const BEFORE_NEGATIVE: [&str; 11] = ["=", "[", ",", "(", "==", "!=", "<", "<=", ">", ">=", ":"];
/// Characters a time-of-day may use after the `T` of a date.
const TIME_CHARS: &str = "0123456789:.Z";

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Tok {
    Ident(String),
    Str(String),
    /// A number as written; the grammar decides between integer and float.
    Num(String),
    Date {
        raw: String,
        ms: u64,
    },
    Punct(&'static str),
    Eof,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Token {
    pub tok: Tok,
    pub span: Span,
    /// First token of its line.
    pub bol: bool,
}

/// A `//` comment: `text` has the marker, one leading space and the trailing spaces removed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Comment {
    pub text: String,
    pub span: Span,
    /// No token comes before it on its line.
    pub own_line: bool,
}

pub(crate) struct Lexed {
    pub tokens: Vec<Token>,
    pub comments: Vec<Comment>,
    pub errors: Vec<Raw>,
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn punct1(c: char) -> Option<&'static str> {
    let at = PUNCT1.find(c)?;
    PUNCT1.get(at..=at)
}

struct Scanner {
    chars: Vec<char>,
    at: usize,
    line: u32,
    col: u32,
}

impl Scanner {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek(0)?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn here(&self, len: usize) -> Span {
        Span {
            line: self.line,
            col: self.col,
            len: u32::try_from(len).unwrap_or(u32::MAX),
        }
    }

    fn take_while(&mut self, mut keep: impl FnMut(char) -> bool) -> String {
        let mut out = String::new();
        while let Some(c) = self.peek(0) {
            if !keep(c) {
                break;
            }
            out.push(c);
            self.bump();
        }
        out
    }

    fn digits_at(&self, from: usize, count: usize) -> bool {
        (0..count).all(|i| self.peek(from + i).is_some_and(|c| c.is_ascii_digit()))
    }

    /// Length of a date-shaped word at the cursor (`2026-01-01`, optionally with a `T` time), or 0.
    fn date_len(&self) -> usize {
        let shaped = self.digits_at(0, 4)
            && self.peek(4) == Some('-')
            && self.digits_at(5, 2)
            && self.peek(7) == Some('-')
            && self.digits_at(8, 2);
        if !shaped {
            return 0;
        }
        let mut len = 10;
        if self.peek(len) == Some('T') {
            len += 1;
            while self.peek(len).is_some_and(|c| TIME_CHARS.contains(c)) {
                len += 1;
            }
        }
        if self.peek(len).is_some_and(|c| is_word(c) || c == '-') {
            return 0;
        }
        len
    }

    fn number_len(&self, signed: bool) -> usize {
        let start = usize::from(signed);
        let mut len = start;
        while self.peek(len).is_some_and(|c| c.is_ascii_digit()) {
            len += 1;
        }
        if len == start {
            return 0;
        }
        if self.peek(len) == Some('.') && self.digits_at(len + 1, 1) {
            len += 1;
            while self.peek(len).is_some_and(|c| c.is_ascii_digit()) {
                len += 1;
            }
        }
        if self.peek(len).is_some_and(|c| is_word(c) || c == '.' || c == '-') {
            return 0;
        }
        len
    }

    fn ident(&mut self) -> String {
        let mut out = self.take_while(is_word);
        while matches!(self.peek(0), Some('.' | '-')) && self.peek(1).is_some_and(is_word) {
            if let Some(joiner) = self.bump() {
                out.push(joiner);
            }
            out.push_str(&self.take_while(is_word));
        }
        out
    }
}

/// Splits `source` into tokens and comments. Every lexical error is collected; the stream keeps
/// going so one pass reports them all.
pub(crate) fn lex(source: &str) -> Lexed {
    let mut sc = Scanner {
        chars: source.chars().collect(),
        at: 0,
        line: 1,
        col: 1,
    };
    let mut out = Lexed {
        tokens: Vec::new(),
        comments: Vec::new(),
        errors: Vec::new(),
    };
    let mut token_line = 0;
    while let Some(c) = sc.peek(0) {
        if c.is_whitespace() {
            sc.bump();
            continue;
        }
        let start = sc.here(1);
        if c == '/' && sc.peek(1) == Some('/') {
            sc.bump();
            sc.bump();
            let raw = sc.take_while(|c| c != '\n');
            let text = raw.strip_prefix(' ').unwrap_or(&raw).trim_end().to_string();
            let len = raw.chars().count() + 2;
            out.comments.push(Comment {
                text,
                span: Span {
                    len: u32::try_from(len).unwrap_or(u32::MAX),
                    ..start
                },
                own_line: token_line != start.line,
            });
            continue;
        }
        let bol = token_line != start.line;
        token_line = start.line;
        let previous_allows_negative = match out.tokens.last().map(|t| &t.tok) {
            Some(Tok::Punct(p)) => BEFORE_NEGATIVE.contains(p),
            _ => false,
        };
        let (tok, span) = if c == '"' {
            match string(&mut sc, &mut out.errors) {
                Some(done) => done,
                None => continue,
            }
        } else if let Some(done) = date(&mut sc, &mut out.errors) {
            match done {
                Some(done) => done,
                None => continue,
            }
        } else if let Some(done) = number(&mut sc, previous_allows_negative) {
            done
        } else if c.is_ascii_alphanumeric() || c == '_' {
            let text = sc.ident();
            let len = text.chars().count();
            (
                Tok::Ident(text),
                Span {
                    len: u32::try_from(len).unwrap_or(u32::MAX),
                    ..start
                },
            )
        } else if let Some(p) = PUNCT2
            .iter()
            .copied()
            .find(|p| p.starts_with(c) && p.chars().nth(1) == sc.peek(1))
        {
            sc.bump();
            sc.bump();
            (Tok::Punct(p), Span { len: 2, ..start })
        } else if let Some(p) = punct1(c) {
            sc.bump();
            (Tok::Punct(p), start)
        } else {
            sc.bump();
            out.errors.push(Raw::new(start, format!("unexpected character {c:?}")));
            continue;
        };
        out.tokens.push(Token { tok, span, bol });
    }
    out.tokens.push(Token {
        tok: Tok::Eof,
        span: sc.here(1),
        bol: true,
    });
    out
}

fn string(sc: &mut Scanner, errors: &mut Vec<Raw>) -> Option<(Tok, Span)> {
    let start = sc.here(1);
    let began = sc.at;
    sc.bump();
    let mut text = String::new();
    loop {
        match sc.peek(0) {
            Some('"') => {
                sc.bump();
                let len = sc.at - began;
                return Some((
                    Tok::Str(text),
                    Span {
                        len: u32::try_from(len).unwrap_or(u32::MAX),
                        ..start
                    },
                ));
            }
            Some('\\') => {
                let at = sc.here(2);
                sc.bump();
                match sc.bump() {
                    Some('n') => text.push('\n'),
                    Some('t') => text.push('\t'),
                    Some('r') => text.push('\r'),
                    Some(c @ ('"' | '\\')) => text.push(c),
                    other => {
                        let shown = other.map_or_else(String::new, |c| c.to_string());
                        errors.push(
                            Raw::new(at, format!("unknown escape \"\\{shown}\""))
                                .hint("the escapes are \\n, \\t, \\r, \\\" and \\\\"),
                        );
                    }
                }
            }
            Some(c) if c != '\n' => {
                text.push(c);
                sc.bump();
            }
            _ => {
                let len = sc.at - began;
                errors.push(
                    Raw::new(
                        Span {
                            len: u32::try_from(len).unwrap_or(u32::MAX),
                            ..start
                        },
                        "string is not closed",
                    )
                    .hint("add the closing double quote on the same line"),
                );
                return None;
            }
        }
    }
}

/// `None`: not a date. `Some(None)`: a date-shaped word that is not a valid date (already reported).
fn date(sc: &mut Scanner, errors: &mut Vec<Raw>) -> Option<Option<(Tok, Span)>> {
    let len = sc.date_len();
    if len == 0 {
        return None;
    }
    let start = sc.here(len);
    let raw: String = (0..len).filter_map(|i| sc.peek(i)).collect();
    for _ in 0..len {
        sc.bump();
    }
    match time::parse(&raw) {
        Ok(ms) => Some(Some((Tok::Date { raw, ms }, start))),
        Err(reason) => {
            errors.push(
                Raw::new(start, format!("invalid date \"{raw}\": {reason}"))
                    .hint("dates are UTC: use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, with the trailing Z"),
            );
            Some(None)
        }
    }
}

fn number(sc: &mut Scanner, allow_negative: bool) -> Option<(Tok, Span)> {
    let signed = allow_negative && sc.peek(0) == Some('-');
    let len = sc.number_len(signed);
    if len == 0 {
        return None;
    }
    let start = sc.here(len);
    let raw: String = (0..len).filter_map(|i| sc.peek(i)).collect();
    for _ in 0..len {
        sc.bump();
    }
    Some((Tok::Num(raw), start))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<Tok> {
        lex(source).tokens.into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn tokens_carry_line_and_column() {
        let lexed = lex("language blocks\n  strategy = deny_overrides\n");
        let strategy = &lexed.tokens[2];
        assert_eq!(strategy.tok, Tok::Ident("strategy".into()));
        assert_eq!((strategy.span.line, strategy.span.col, strategy.span.len), (2, 3, 8));
        assert!(strategy.bol);
        assert!(!lexed.tokens[3].bol);
    }

    #[test]
    fn identifiers_join_dots_and_dashes_but_arrow_stays_punctuation() {
        assert_eq!(
            kinds("project.view a-b parent->member"),
            vec![
                Tok::Ident("project.view".into()),
                Tok::Ident("a-b".into()),
                Tok::Ident("parent".into()),
                Tok::Punct("->"),
                Tok::Ident("member".into()),
                Tok::Eof,
            ]
        );
    }

    #[test]
    fn dates_are_utc_and_zone_is_required_for_a_time() {
        assert_eq!(
            kinds("2026-01-01")[0],
            Tok::Date {
                raw: "2026-01-01".into(),
                ms: 1_767_225_600_000
            }
        );
        let lexed = lex("  2026-01-01T09:00:00");
        let error = &lexed.errors[0];
        assert_eq!((error.span.line, error.span.col, error.span.len), (1, 3, 19));
        assert!(error.message.contains("invalid date"), "{}", error.message);
    }

    #[test]
    fn negative_numbers_only_after_an_operator() {
        assert_eq!(kinds("= -3")[1], Tok::Num("-3".into()));
        assert_eq!(kinds("a - 3")[1..3], [Tok::Punct("-"), Tok::Num("3".into())]);
    }

    #[test]
    fn comments_are_lifted_out_with_their_placement() {
        let lexed = lex("// head\nstrategy = x // tail\n");
        assert_eq!(lexed.comments.len(), 2);
        assert_eq!(lexed.comments[0].text, "head");
        assert!(lexed.comments[0].own_line);
        assert_eq!(lexed.comments[1].text, "tail");
        assert!(!lexed.comments[1].own_line);
        assert_eq!((lexed.comments[1].span.line, lexed.comments[1].span.col), (2, 14));
    }

    #[test]
    fn unclosed_string_and_unknown_escape_are_positioned() {
        let lexed = lex("a = \"open\nb = \"x\\q\"");
        assert_eq!(lexed.errors.len(), 2);
        assert_eq!((lexed.errors[0].span.line, lexed.errors[0].span.col), (1, 5));
        assert_eq!(lexed.errors[0].message, "string is not closed");
        assert_eq!((lexed.errors[1].span.line, lexed.errors[1].span.col), (2, 7));
    }

    #[test]
    fn unexpected_character_is_reported_and_skipped() {
        let lexed = lex("a ? b");
        assert_eq!(lexed.errors.len(), 1);
        assert_eq!(lexed.errors[0].span.col, 3);
        assert_eq!(lexed.tokens.len(), 3);
    }
}
