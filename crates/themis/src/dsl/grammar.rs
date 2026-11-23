//! The sub-grammars every syntax shares: values, anchors and paths, tuples, conditions, relation
//! rewrites and subject matchers. A syntax drives a [`Cursor`] and calls these where its own
//! text holds one of those pieces.

use crate::dsl::error::{PResult, Raw, Span};
use crate::dsl::lex::{Tok, Token};
use crate::{
    Anchor, Condition, ObjectRef, Operand, Rewrite, SubjectMatcher, TargetSelector, Tuple,
    TupleSubject, Value,
};

/// How deep nested groups, lists and conditions may go: input is external and unbounded.
const MAX_DEPTH: u32 = 64;
/// The roots an attribute path may start at.
const ATTR_ROOTS: [&str; 3] = ["subject", "resource", "env"];

/// A value with the place it was read at.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Sp<T> {
    pub v: T,
    pub span: Span,
}

/// An anchor as written: `kind` or `kind:id`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AnchorAt {
    pub anchor: Anchor,
    pub span: Span,
}

pub(crate) struct Cursor {
    tokens: Vec<Token>,
    at: usize,
    depth: u32,
}

impl Cursor {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            at: 0,
            depth: 0,
        }
    }

    pub fn index(&self) -> usize {
        self.at
    }

    fn eof_token() -> Token {
        Token {
            tok: Tok::Eof,
            span: Span::default(),
            bol: true,
        }
    }

    pub fn current(&self) -> Token {
        self.tokens
            .get(self.at)
            .or_else(|| self.tokens.last())
            .cloned()
            .unwrap_or_else(Self::eof_token)
    }

    pub fn peek_is_punct(&self, punct: &str) -> bool {
        matches!(self.tokens.get(self.at + 1), Some(Token { tok: Tok::Punct(p), .. }) if *p == punct)
    }

    pub fn span(&self) -> Span {
        self.current().span
    }

    /// The span of the last token consumed, for the end of an element.
    pub fn previous_span(&self) -> Span {
        self.at
            .checked_sub(1)
            .and_then(|i| self.tokens.get(i))
            .map(|t| t.span)
            .unwrap_or_default()
    }

    pub fn at_eof(&self) -> bool {
        matches!(self.current().tok, Tok::Eof)
    }

    pub fn advance(&mut self) {
        if !self.at_eof() {
            self.at += 1;
        }
    }

    pub fn is_punct(&self, punct: &str) -> bool {
        matches!(self.current().tok, Tok::Punct(p) if p == punct)
    }

    pub fn eat_punct(&mut self, punct: &str) -> bool {
        let found = self.is_punct(punct);
        if found {
            self.advance();
        }
        found
    }

    pub fn expect_punct(&mut self, punct: &str, why: &str) -> PResult<Span> {
        let token = self.current();
        if matches!(token.tok, Tok::Punct(p) if p == punct) {
            self.advance();
            return Ok(token.span);
        }
        Err(Raw::new(
            token.span,
            format!("expected `{punct}` {why}, found {}", describe(&token.tok)),
        ))
    }

    pub fn is_word(&self, word: &str) -> bool {
        matches!(self.current().tok, Tok::Ident(w) if w == word)
    }

    pub fn eat_word(&mut self, word: &str) -> bool {
        let found = self.is_word(word);
        if found {
            self.advance();
        }
        found
    }

    pub fn word(&mut self, what: &str) -> PResult<Sp<String>> {
        let token = self.current();
        match token.tok {
            Tok::Ident(v) => {
                self.advance();
                Ok(Sp { v, span: token.span })
            }
            other => Err(Raw::new(
                token.span,
                format!("expected {what}, found {}", describe(&other)),
            )),
        }
    }

    pub fn string(&mut self, what: &str) -> PResult<Sp<String>> {
        let token = self.current();
        match token.tok {
            Tok::Str(v) => {
                self.advance();
                Ok(Sp { v, span: token.span })
            }
            other => Err(Raw::new(
                token.span,
                format!("expected {what} in quotes, found {}", describe(&other)),
            )),
        }
    }

    pub fn date(&mut self) -> PResult<Sp<u64>> {
        let token = self.current();
        match token.tok {
            Tok::Date { ms, .. } => {
                self.advance();
                Ok(Sp { v: ms, span: token.span })
            }
            other => Err(Raw::new(
                token.span,
                format!("expected a UTC date, found {}", describe(&other)),
            )
            .hint("write it as 2026-01-31T12:00:00Z")),
        }
    }

    pub fn number(&mut self) -> PResult<Sp<usize>> {
        let token = self.current();
        match &token.tok {
            Tok::Num(raw) => match raw.parse::<usize>() {
                Ok(v) => {
                    self.advance();
                    Ok(Sp { v, span: token.span })
                }
                Err(_) => Err(Raw::new(
                    token.span,
                    format!("`{raw}` is not a whole number that fits here"),
                )),
            },
            other => Err(Raw::new(
                token.span,
                format!("expected a number, found {}", describe(other)),
            )),
        }
    }

    pub fn enter(&mut self) -> PResult<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Raw::new(self.span(), "nested too deeply")
                .hint(format!("the limit is {MAX_DEPTH} levels")));
        }
        Ok(())
    }

    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn fail<T>(&self, span: Span, message: impl Into<String>) -> PResult<T> {
        Err(Raw::new(span, message))
    }
}

/// A short description of a token for "found ..." messages.
pub(crate) fn describe(tok: &Tok) -> String {
    match tok {
        Tok::Ident(w) => format!("`{w}`"),
        Tok::Str(_) => "a string".to_string(),
        Tok::Num(raw) => format!("the number {raw}"),
        Tok::Date { raw, .. } => format!("the date {raw}"),
        Tok::Punct(p) => format!("`{p}`"),
        Tok::Eof => "the end of the file".to_string(),
    }
}

/// "did you mean ...?" when a candidate is close, otherwise the list of valid names.
pub(crate) fn suggest(name: &str, candidates: &[&str]) -> String {
    let best = candidates
        .iter()
        .map(|c| (edit_distance(name, c), *c))
        .min_by_key(|(d, _)| *d);
    match best {
        Some((d, c)) if d <= 2.max(name.chars().count() / 3) => format!("did you mean `{c}`?"),
        _ => format!("expected one of: {}", candidates.join(", ")),
    }
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let above = row[j + 1];
            row[j + 1] = (diagonal + usize::from(ca != *cb))
                .min(row[j] + 1)
                .min(above + 1);
            diagonal = above;
        }
    }
    row[b.len()]
}

// ---- values ----------------------------------------------------------------------------------

pub(crate) fn literal(cur: &mut Cursor) -> PResult<Value> {
    let token = cur.current();
    match token.tok {
        Tok::Str(v) => {
            cur.advance();
            Ok(Value::Str(v))
        }
        Tok::Num(raw) => {
            cur.advance();
            number_value(&raw, token.span)
        }
        Tok::Date { ms, .. } => {
            cur.advance();
            i64::try_from(ms)
                .map(Value::Int)
                .map_err(|_| Raw::new(token.span, "this date is out of range"))
        }
        Tok::Ident(w) if w == "true" || w == "false" => {
            cur.advance();
            Ok(Value::Bool(w == "true"))
        }
        Tok::Ident(w) if w == "null" => {
            cur.advance();
            Ok(Value::Null)
        }
        Tok::Punct("[") => {
            cur.advance();
            cur.enter()?;
            let mut items = Vec::new();
            while !cur.is_punct("]") {
                items.push(literal(cur)?);
                if !cur.eat_punct(",") {
                    break;
                }
            }
            cur.expect_punct("]", "to close the list")?;
            cur.leave();
            Ok(Value::List(items))
        }
        other => Err(Raw::new(
            token.span,
            format!(
                "expected a value (string, number, true, false, null, date or list), found {}",
                describe(&other)
            ),
        )),
    }
}

fn number_value(raw: &str, span: Span) -> PResult<Value> {
    if let Ok(int) = raw.parse::<i64>() {
        return Ok(Value::Int(int));
    }
    match raw.parse::<f64>() {
        Ok(float) if float.is_finite() => Ok(Value::Float(float)),
        _ => Err(Raw::new(span, format!("`{raw}` is not a number that fits here"))),
    }
}

/// `[a, b, c]`
pub(crate) fn word_list(cur: &mut Cursor, what: &str) -> PResult<Vec<Sp<String>>> {
    cur.expect_punct("[", &format!("to start the {what}"))?;
    let mut items = Vec::new();
    while !cur.is_punct("]") {
        items.push(cur.word(&format!("an entry of the {what}"))?);
        if !cur.eat_punct(",") {
            break;
        }
    }
    cur.expect_punct("]", &format!("to close the {what}"))?;
    Ok(items)
}

// ---- anchors, paths, tuples ---------------------------------------------------------------

fn id_part(cur: &mut Cursor) -> PResult<String> {
    let token = cur.current();
    match token.tok {
        Tok::Ident(v) | Tok::Num(v) => {
            cur.advance();
            Ok(v)
        }
        Tok::Punct("*") => {
            cur.advance();
            Ok("*".to_string())
        }
        other => Err(Raw::new(
            token.span,
            format!("expected an id after `:`, found {}", describe(&other)),
        )),
    }
}

/// `kind` or `kind:id`
pub(crate) fn anchor(cur: &mut Cursor) -> PResult<AnchorAt> {
    let kind = cur.word("a kind (for example `project` or `project:roadmap`)")?;
    let id = if cur.eat_punct(":") {
        Some(id_part(cur)?)
    } else {
        None
    };
    Ok(AnchorAt {
        anchor: Anchor { kind: kind.v, id },
        span: kind.span,
    })
}

pub(crate) fn target(cur: &mut Cursor) -> PResult<TargetSelector> {
    let at = anchor(cur)?;
    Ok(TargetSelector {
        kind: at.anchor.kind,
        id: at.anchor.id,
    })
}

/// `a > b:1 > c`
pub(crate) fn path(cur: &mut Cursor) -> PResult<Vec<AnchorAt>> {
    let mut steps = vec![anchor(cur)?];
    while cur.eat_punct(">") {
        steps.push(anchor(cur)?);
    }
    Ok(steps)
}

fn object_ref(at: AnchorAt, what: &str) -> PResult<ObjectRef> {
    match at.anchor.id {
        Some(id) => Ok(ObjectRef {
            kind: at.anchor.kind,
            id,
        }),
        None => Err(Raw::new(at.span, format!("{what} needs an id"))
            .hint("write kind:id#relation@kind:id")),
    }
}

/// `kind:id#relation@kind:id` or `kind:id#relation@kind:id#relation`
pub(crate) fn tuple(cur: &mut Cursor) -> PResult<(Tuple, Span)> {
    let first = anchor(cur)?;
    let span = first.span;
    let object = object_ref(first, "a tuple object")?;
    cur.expect_punct("#", "between the object and its relation")?;
    let relation = cur.word("a relation name")?;
    cur.expect_punct("@", "before the subject")?;
    let subject_at = anchor(cur)?;
    let subject = object_ref(subject_at, "a tuple subject")?;
    let subject = if cur.eat_punct("#") {
        TupleSubject::Userset(subject, cur.word("a relation name")?.v)
    } else {
        TupleSubject::Object(subject)
    };
    Ok((
        Tuple {
            object,
            relation: relation.v,
            subject,
        },
        span,
    ))
}

// ---- subject matchers ---------------------------------------------------------------------

/// `anyone`, `role r`, `user u`, `principal p` or `relation r`
pub(crate) fn matcher(cur: &mut Cursor) -> PResult<SubjectMatcher> {
    let head = cur.word("a subject matcher (role, user, principal, relation or anyone)")?;
    match head.v.as_str() {
        "any" | "anyone" => Ok(SubjectMatcher::Any),
        "role" => Ok(SubjectMatcher::Role {
            id: cur.word("a role name")?.v,
        }),
        "user" => {
            let token = cur.current();
            match token.tok {
                Tok::Ident(id) | Tok::Num(id) => {
                    cur.advance();
                    Ok(SubjectMatcher::User { id })
                }
                other => Err(Raw::new(
                    token.span,
                    format!("expected a user id, found {}", describe(&other)),
                )),
            }
        }
        "principal" => Ok(SubjectMatcher::Principal {
            name: cur.word("a principal name")?.v,
        }),
        "relation" => Ok(SubjectMatcher::Relation {
            relation: cur.word("a relation name")?.v,
        }),
        other => Err(Raw::new(head.span, format!("unknown subject matcher `{other}`"))
            .hint("use role, user, principal, relation or anyone")),
    }
}

// ---- conditions ---------------------------------------------------------------------------

pub(crate) fn condition(cur: &mut Cursor) -> PResult<Condition> {
    cur.enter()?;
    let first = and_expr(cur)?;
    let result = if cur.is_word("or") || cur.is_punct("||") {
        let mut of = vec![first];
        while cur.eat_word("or") || cur.eat_punct("||") {
            of.push(and_expr(cur)?);
        }
        Condition::Any { of }
    } else {
        first
    };
    cur.leave();
    Ok(result)
}

fn and_expr(cur: &mut Cursor) -> PResult<Condition> {
    let first = not_expr(cur)?;
    if !(cur.is_word("and") || cur.is_punct("&&")) {
        return Ok(first);
    }
    let mut of = vec![first];
    while cur.eat_word("and") || cur.eat_punct("&&") {
        of.push(not_expr(cur)?);
    }
    Ok(Condition::All { of })
}

fn not_expr(cur: &mut Cursor) -> PResult<Condition> {
    if cur.eat_word("not") || cur.eat_punct("!") {
        cur.enter()?;
        let inner = not_expr(cur)?;
        cur.leave();
        return Ok(Condition::Not {
            cond: Box::new(inner),
        });
    }
    atom(cur)
}

fn attr_path(word: &Sp<String>) -> PResult<()> {
    let rooted = word
        .v
        .split_once('.')
        .is_some_and(|(root, _)| ATTR_ROOTS.contains(&root));
    if rooted {
        Ok(())
    } else {
        Err(Raw::new(word.span, format!("`{}` is not an attribute", word.v))
            .hint("attributes start with subject., resource. or env.; text goes in quotes"))
    }
}

fn operand(cur: &mut Cursor) -> PResult<Operand> {
    let token = cur.current();
    if let Tok::Ident(w) = &token.tok {
        if w != "true" && w != "false" && w != "null" {
            let word = cur.word("a value")?;
            attr_path(&word).map_err(|e| {
                Raw::new(e.span, format!("`{}` is not a value", word.v))
                    .hint("attributes start with subject., resource. or env.; text goes in quotes")
            })?;
            return Ok(Operand::Attr { attr: word.v });
        }
    }
    Ok(Operand::Lit(literal(cur)?))
}

fn atom(cur: &mut Cursor) -> PResult<Condition> {
    if cur.eat_punct("(") {
        let inner = condition(cur)?;
        cur.expect_punct(")", "to close the group")?;
        return Ok(inner);
    }
    if (cur.is_word("all") || cur.is_word("any")) && cur.peek_is_punct("(") {
        let is_all = cur.is_word("all");
        cur.advance();
        cur.advance();
        let mut of = Vec::new();
        while !cur.is_punct(")") {
            of.push(condition(cur)?);
            if !cur.eat_punct(",") {
                break;
            }
        }
        cur.expect_punct(")", "to close the list")?;
        return Ok(if is_all {
            Condition::All { of }
        } else {
            Condition::Any { of }
        });
    }
    if cur.eat_word("exists") {
        let word = cur.word("an attribute")?;
        attr_path(&word)?;
        return Ok(Condition::Exists { attr: word.v });
    }
    if cur.eat_punct("@") {
        let func = cur.word("a function name")?;
        cur.expect_punct("(", "after the function name")?;
        let mut args = Vec::new();
        while !cur.is_punct(")") {
            args.push(operand(cur)?);
            if !cur.eat_punct(",") {
                break;
            }
        }
        cur.expect_punct(")", "to close the arguments")?;
        return Ok(Condition::Call { func: func.v, args });
    }
    let left = operand(cur)?;
    if cur.eat_word("in") {
        let set = operand(cur)?;
        return Ok(Condition::In { item: left, set });
    }
    let token = cur.current();
    let build: Option<fn(Operand, Operand) -> Condition> = match token.tok {
        Tok::Punct("==") => Some(Condition::eq),
        Tok::Punct("!=") => Some(Condition::ne),
        Tok::Punct("<") => Some(Condition::lt),
        Tok::Punct("<=") => Some(Condition::le),
        Tok::Punct(">") => Some(Condition::gt),
        Tok::Punct(">=") => Some(Condition::ge),
        _ => None,
    };
    match build {
        Some(build) => {
            cur.advance();
            Ok(build(left, operand(cur)?))
        }
        None => Err(Raw::new(
            token.span,
            format!(
                "expected a comparison (==, !=, <, <=, >, >=, in) after the value, found {}",
                describe(&token.tok)
            ),
        )),
    }
}

// ---- relation rewrites --------------------------------------------------------------------

fn rewrite_primary(cur: &mut Cursor) -> PResult<Rewrite> {
    if cur.eat_punct("(") {
        let inner = rewrite(cur)?;
        cur.expect_punct(")", "to close the group")?;
        return Ok(inner);
    }
    let word = cur.word("a relation, `this` or a group")?;
    if word.v == "this" {
        return Ok(Rewrite::This);
    }
    let is_group = matches!(word.v.as_str(), "union" | "intersection" | "exclusion");
    if is_group && cur.eat_punct("(") {
        cur.enter()?;
        let mut of = Vec::new();
        while !cur.is_punct(")") {
            of.push(rewrite(cur)?);
            if !cur.eat_punct(",") {
                break;
            }
        }
        cur.expect_punct(")", "to close the list")?;
        cur.leave();
        return match word.v.as_str() {
            "union" => Ok(Rewrite::Union { of }),
            "intersection" => Ok(Rewrite::Intersection { of }),
            _ => {
                let [base, subtract]: [Rewrite; 2] = of.try_into().map_err(|_| {
                    Raw::new(
                        word.span,
                        "exclusion takes exactly two operands: the base and what to subtract",
                    )
                })?;
                Ok(Rewrite::Exclusion {
                    base: Box::new(base),
                    subtract: Box::new(subtract),
                })
            }
        };
    }
    if cur.eat_punct("->") {
        return Ok(Rewrite::TupleToUserset {
            tupleset: word.v,
            computed: cur.word("a relation on the parent")?.v,
        });
    }
    Ok(Rewrite::Computed { relation: word.v })
}

pub(crate) fn rewrite(cur: &mut Cursor) -> PResult<Rewrite> {
    cur.enter()?;
    let first = rewrite_primary(cur)?;
    let mut items = vec![first];
    let mut operator: Option<&'static str> = None;
    loop {
        let token = cur.current();
        let this_op = match token.tok {
            Tok::Punct("|") => "|",
            Tok::Punct("&") => "&",
            Tok::Punct("-") => "-",
            _ => break,
        };
        if operator.is_some_and(|op| op != this_op) {
            return Err(Raw::new(token.span, "cannot mix `|`, `&` and `-` without parentheses")
                .hint("group the inner part, for example (a | b) - c"));
        }
        operator = Some(this_op);
        cur.advance();
        items.push(rewrite_primary(cur)?);
    }
    cur.leave();
    match operator {
        None => Ok(items.remove(0)),
        Some("-") => {
            let span = cur.previous_span();
            let [base, subtract]: [Rewrite; 2] = items.try_into().map_err(|_| {
                Raw::new(span, "exclusion takes two operands: a - b")
                    .hint("nest groups for more")
            })?;
            Ok(Rewrite::Exclusion {
                base: Box::new(base),
                subtract: Box::new(subtract),
            })
        }
        Some("|") => Ok(Rewrite::Union { of: items }),
        Some(_) => Ok(Rewrite::Intersection { of: items }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::lex::lex;

    fn cursor(text: &str) -> Cursor {
        Cursor::new(lex(text).tokens)
    }

    #[test]
    fn condition_reads_precedence_and_attributes() {
        let cond = condition(&mut cursor("subject.dept == \"it\" or not exists env.mfa && 1 < 2"))
            .unwrap();
        let Condition::Any { of } = cond else {
            panic!("expected an or at the top")
        };
        assert_eq!(of.len(), 2);
        assert!(matches!(of[1], Condition::All { .. }));
    }

    #[test]
    fn a_bare_word_is_not_a_value_and_the_error_points_at_it() {
        let err = condition(&mut cursor("  a == 1")).unwrap_err();
        assert_eq!((err.span.line, err.span.col), (1, 3));
        assert!(err.message.contains("not an attribute") || err.message.contains("not a value"));
    }

    #[test]
    fn rewrite_refuses_mixed_operators() {
        let err = rewrite(&mut cursor("a | b & c")).unwrap_err();
        assert_eq!(err.span.col, 7);
        assert!(err.hint.is_some());
    }

    #[test]
    fn rewrite_reads_arrow_and_exclusion() {
        let parsed = rewrite(&mut cursor("this | parent->viewer - banned")).unwrap_err();
        assert!(parsed.message.contains("mix"));
        let ok = rewrite(&mut cursor("(this | parent->viewer) - banned")).unwrap();
        assert!(matches!(ok, Rewrite::Exclusion { .. }));
    }

    #[test]
    fn tuple_needs_ids_on_both_sides() {
        let err = tuple(&mut cursor("doc#viewer@user:ana")).unwrap_err();
        assert_eq!(err.span.col, 1);
        let (t, _) = tuple(&mut cursor("doc:1#viewer@group:9#member")).unwrap();
        assert_eq!(t.to_string(), "doc:1#viewer@group:9#member");
    }

    #[test]
    fn nesting_beyond_the_limit_is_refused() {
        let text = format!("{}1 == 1{}", "(".repeat(70), ")".repeat(70));
        let err = condition(&mut cursor(&text)).unwrap_err();
        assert!(err.message.contains("deeply"));
    }

    #[test]
    fn suggestions_name_the_closest_candidate() {
        assert_eq!(suggest("grnt", &["grant", "role"]), "did you mean `grant`?");
        assert!(suggest("zzzzzzzz", &["grant", "role"]).starts_with("expected one of"));
    }
}
