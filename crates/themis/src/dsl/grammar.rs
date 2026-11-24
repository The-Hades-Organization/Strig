//! The sub-grammars every syntax shares: values, anchors and paths, tuples, conditions, relation
//! rewrites and subject matchers. A syntax drives a [`Cursor`] and calls these where its own
//! text holds one of those pieces.

use std::collections::BTreeMap;

use crate::dsl::error::{PResult, Raw, Span};
use crate::dsl::lex::{Tok, Token};
use crate::{
    Anchor, Condition, ObjectRef, Operand, Rewrite, RoleAssignment, Subject, SubjectMatcher, TargetSelector, Tuple,
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
    /// The token index where the current statement ends: from there on the cursor reads the end.
    fence: Option<usize>,
}

impl Cursor {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            at: 0,
            depth: 0,
            fence: None,
        }
    }

    /// The indices where a statement starts: the first token of every line, or, with a margin,
    /// of every line that is not indented deeper than it (the deeper ones continue the line above).
    pub fn statements(&self, margin: Option<u32>) -> Vec<usize> {
        let mut starts = Vec::new();
        for (at, token) in self.tokens.iter().enumerate() {
            if token.tok == Tok::Eof || !token.bol {
                continue;
            }
            if starts.is_empty() || margin.is_none_or(|m| token.span.col <= m) {
                starts.push(at);
            }
        }
        starts
    }

    /// Where the tokens end: the fence of the last statement.
    pub fn end(&self) -> usize {
        self.tokens.len().saturating_sub(1)
    }

    /// The column of the token at `at`.
    pub fn column_at(&self, at: usize) -> u32 {
        self.tokens.get(at).map_or(1, |t| t.span.col)
    }

    /// Starts reading the statement that spans the tokens `at..fence`.
    pub fn goto(&mut self, at: usize, fence: usize) {
        self.at = at;
        self.fence = Some(fence);
        self.depth = 0;
    }

    /// The token `ahead` places on, or the end.
    pub fn peek(&self, ahead: usize) -> Tok {
        let at = self.at + ahead;
        if self.fence.is_some_and(|f| at >= f) {
            return Tok::Eof;
        }
        self.tokens.get(at).map_or(Tok::Eof, |t| t.tok.clone())
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
        if self.fence.is_some_and(|f| self.at >= f) {
            let last = self.previous_span();
            return Token {
                tok: Tok::Eof,
                span: Span {
                    line: last.line,
                    col: last.col + last.len.max(1),
                    len: 1,
                },
                bol: true,
            };
        }
        self.tokens
            .get(self.at)
            .or_else(|| self.tokens.last())
            .cloned()
            .unwrap_or_else(Self::eof_token)
    }

    pub fn peek_is_punct(&self, punct: &str) -> bool {
        matches!(self.peek(1), Tok::Punct(p) if p == punct)
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
                Ok(Sp {
                    v: ms,
                    span: token.span,
                })
            }
            other => Err(
                Raw::new(token.span, format!("expected a UTC date, found {}", describe(&other)))
                    .hint("write it as 2026-01-31T12:00:00Z"),
            ),
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
            return Err(Raw::new(self.span(), "nested too deeply").hint(format!("the limit is {MAX_DEPTH} levels")));
        }
        Ok(())
    }

    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Forgets the nesting of an element that failed half-read: a `?` skips the `leave` calls, and
    /// the reading resumes at the top level.
    pub fn reset_depth(&mut self) {
        self.depth = 0;
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

/// The candidate nearest to `name`, when it is a slip away from it. On a tie in distance the
/// first in alphabetical order wins, so the answer does not depend on the order of `candidates`.
pub(crate) fn closest<'a>(name: &str, candidates: &[&'a str]) -> Option<&'a str> {
    candidates
        .iter()
        .map(|c| (edit_distance(name, c), *c))
        .min()
        .filter(|(d, _)| *d <= 2.max(name.chars().count() / 3))
        .map(|(_, c)| c)
}

/// "did you mean ...?" when a candidate is close, otherwise the list of valid names.
pub(crate) fn suggest(name: &str, candidates: &[&str]) -> String {
    match closest(name, candidates) {
        Some(c) => format!("did you mean `{c}`?"),
        None => format!("expected one of: {}", candidates.join(", ")),
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
            row[j + 1] = (diagonal + usize::from(ca != *cb)).min(row[j] + 1).min(above + 1);
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
    if !raw.contains('.') {
        return Err(Raw::new(span, format!("`{raw}` does not fit in a whole number")).hint(
            "whole numbers go from -9223372036854775808 to 9223372036854775807; write a decimal point for a float",
        ));
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
    let id = if cur.eat_punct(":") { Some(id_part(cur)?) } else { None };
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
        None => Err(Raw::new(at.span, format!("{what} needs an id")).hint("write kind:id#relation@kind:id")),
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

/// `key = value, key = value`
pub(crate) fn pairs(cur: &mut Cursor) -> PResult<BTreeMap<String, Value>> {
    let mut entries = BTreeMap::new();
    loop {
        let (key, item) = pair(cur)?;
        if entries.insert(key.v.clone(), item).is_some() {
            return Err(Raw::new(key.span, format!("key `{}` is given twice", key.v)));
        }
        if !cur.eat_punct(",") {
            return Ok(entries);
        }
    }
}

fn pair(cur: &mut Cursor) -> PResult<(Sp<String>, Value)> {
    let key = cur.word("a key")?;
    cur.expect_punct("=", &format!("after `{}`", key.v))?;
    Ok((key, literal(cur)?))
}

/// A path and the attributes of the resource: `a > b:1 with tier = "gold", zone = 2`.
pub(crate) fn resource(cur: &mut Cursor) -> PResult<(Vec<AnchorAt>, BTreeMap<String, Value>)> {
    let steps = path(cur)?;
    let attrs = if cur.eat_word("with") {
        pairs(cur)?
    } else {
        BTreeMap::new()
    };
    Ok((steps, attrs))
}

/// What follows the role of an assignment: `in <scope> from <date> until <date>`, in any order.
pub(crate) fn assignment(cur: &mut Cursor, role: String) -> PResult<RoleAssignment> {
    let mut found = RoleAssignment {
        role,
        scope: None,
        valid_from: None,
        valid_until: None,
    };
    loop {
        let word = if cur.is_word("in") || cur.is_word("from") || cur.is_word("until") {
            cur.word("a clause")?
        } else {
            return Ok(found);
        };
        let twice = |w: &Sp<String>| Raw::new(w.span, format!("`{}` is given twice", w.v));
        match word.v.as_str() {
            "in" if found.scope.is_none() => found.scope = Some(anchor(cur)?.anchor),
            "from" if found.valid_from.is_none() => found.valid_from = Some(cur.date()?.v),
            "until" if found.valid_until.is_none() => found.valid_until = Some(cur.date()?.v),
            _ => return Err(twice(&word)),
        }
    }
}

/// A member of an invariant: `kind:id`, or `kind:id (role r in scope, principal p, attr k = v)`.
pub(crate) fn member(cur: &mut Cursor) -> PResult<Subject> {
    let at = anchor(cur)?;
    let Some(id) = at.anchor.id else {
        return Err(Raw::new(at.span, "a member needs an id").hint("write kind:id"));
    };
    let mut subject = Subject::of_kind(at.anchor.kind, id);
    if !cur.eat_punct("(") {
        return Ok(subject);
    }
    loop {
        let word = cur.word("role, principal or attr")?;
        match word.v.as_str() {
            "role" => {
                let role = cur.word("a role name")?;
                subject.roles.push(assignment(cur, role.v)?);
            }
            "principal" => subject.principals.push(cur.word("a principal name")?.v),
            "attr" => {
                let (key, item) = pair(cur)?;
                if subject.attrs.insert(key.v.clone(), item).is_some() {
                    return Err(Raw::new(key.span, format!("key `{}` is given twice", key.v)));
                }
            }
            other => {
                return Err(Raw::new(
                    word.span,
                    format!("a member can have a role, principal or attr, not `{other}`"),
                ));
            }
        }
        if !cur.eat_punct(",") {
            break;
        }
    }
    cur.expect_punct(")", "to close the member")?;
    Ok(subject)
}

/// `[member, member]`
pub(crate) fn members(cur: &mut Cursor) -> PResult<Vec<Subject>> {
    cur.expect_punct("[", "to start the list")?;
    let mut items = Vec::new();
    while !cur.is_punct("]") {
        items.push(member(cur)?);
        if !cur.eat_punct(",") {
            break;
        }
    }
    cur.expect_punct("]", "to close the list")?;
    Ok(items)
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

/// Builds a condition from its two operands.
type BinaryCondition = fn(Operand, Operand) -> Condition;

/// The operators written between two operands as a word, besides `in` and `ip_in`.
const WORD_OPERATORS: [(&str, BinaryCondition); 5] = [
    ("starts_with", Condition::starts_with),
    ("ends_with", Condition::ends_with),
    ("contains", Condition::contains),
    ("any_in", Condition::any_in),
    ("all_in", Condition::all_in),
];

/// A literal CIDR, or list of them, that does not parse is refused here, where it can be pointed
/// at; an attribute holds whatever it holds and is judged at decision time.
fn check_cidrs(set: &Operand, at: Span) -> PResult<()> {
    let texts: Vec<&str> = match set {
        Operand::Lit(Value::Str(text)) => vec![text.as_str()],
        Operand::Lit(Value::List(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => return Ok(()),
    };
    for text in texts {
        crate::condition::check_cidr(text).map_err(|_| {
            Raw::new(at, format!("`{text}` is not a CIDR block"))
                .hint("write an address and a prefix length, like \"10.0.0.0/8\" or \"2001:db8::/32\"")
        })?;
    }
    Ok(())
}

fn string_arg(cur: &mut Cursor, what: &str) -> PResult<(String, Span)> {
    let token = cur.current();
    match token.tok {
        Tok::Str(text) => {
            cur.advance();
            Ok((text, token.span))
        }
        other => Err(Raw::new(
            token.span,
            format!("expected {what} in quotes, found {}", describe(&other)),
        )),
    }
}

fn clock_arg(cur: &mut Cursor, what: &str) -> PResult<String> {
    let (text, span) = string_arg(cur, what)?;
    crate::condition::parse_clock(&text).map_err(|_| {
        Raw::new(span, format!("`{text}` is not a time of day"))
            .hint("write hours and minutes with two digits each, 00:00 to 23:59, like \"09:30\"")
    })?;
    Ok(text)
}

fn time_between(cur: &mut Cursor) -> PResult<Condition> {
    cur.advance();
    let from = clock_arg(cur, "the start time")?;
    let until = clock_arg(cur, "the end time")?;
    Ok(Condition::TimeBetween { from, until })
}

fn weekday_in(cur: &mut Cursor) -> PResult<Condition> {
    cur.advance();
    cur.expect_punct("[", "to open the list of days")?;
    let mut days = Vec::new();
    while !cur.is_punct("]") {
        let (day, span) = string_arg(cur, "a day")?;
        crate::condition::parse_weekday(&day).map_err(|_| {
            Raw::new(span, format!("`{day}` is not a day of the week"))
                .hint("use mon, tue, wed, thu, fri, sat or sun, in lower case")
        })?;
        days.push(day);
        if !cur.eat_punct(",") {
            break;
        }
    }
    cur.expect_punct("]", "to close the list of days")?;
    Ok(Condition::WeekdayIn { days })
}

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
        return Ok(Condition::Not { cond: Box::new(inner) });
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
    if let Tok::Ident(w) = &token.tok
        && w != "true"
        && w != "false"
        && w != "null"
    {
        let word = cur.word("a value")?;
        attr_path(&word).map_err(|e| {
            Raw::new(e.span, format!("`{}` is not a value", word.v))
                .hint("attributes start with subject., resource. or env.; text goes in quotes")
        })?;
        return Ok(Operand::Attr { attr: word.v });
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
    if cur.is_word("time_between") {
        return time_between(cur);
    }
    if cur.is_word("weekday_in") {
        return weekday_in(cur);
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
    if cur.eat_word("ip_in") {
        let at = cur.current().span;
        let set = operand(cur)?;
        check_cidrs(&set, at)?;
        return Ok(Condition::IpIn { item: left, set });
    }
    for (word, build) in WORD_OPERATORS {
        if cur.eat_word(word) {
            return Ok(build(left, operand(cur)?));
        }
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
                "expected a comparison (==, !=, <, <=, >, >=, in, starts_with, ends_with, contains, any_in, all_in, ip_in) after the value, found {}",
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
            let [base, subtract]: [Rewrite; 2] = items
                .try_into()
                .map_err(|_| Raw::new(span, "exclusion takes two operands: a - b").hint("nest groups for more"))?;
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
        let cond = condition(&mut cursor("subject.dept == \"it\" or not exists env.mfa && 1 < 2")).unwrap();
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
