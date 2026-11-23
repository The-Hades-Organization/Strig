//! The Actors syntax: policy grouped by who acts. A heading names a role, user, principal, relation
//! or `anyone`; the lines indented under it say what that actor may do. Reference material
//! (catalog, relations, tuples, engine, governance) follows as sections of plain lines.

use std::collections::{BTreeMap, HashMap};

use crate::dsl::blocks::{duplicate, scoped};
use crate::dsl::blocks_print::{self as bp, Printer};
use crate::dsl::build::Builder;
use crate::dsl::error::{PResult, PrintError, Raw, Span};
use crate::dsl::grammar::{Cursor, anchor, assignment, condition, describe, matcher, pairs, suggest, target};
use crate::dsl::lex::Tok;
use crate::dsl::policy::{Policy, ids};
use crate::dsl::rules;
use crate::{Anchor, Effect, Grant, Subject, SubjectMatcher};

type Printed<T> = Result<T, PrintError>;

const HEADINGS: [&str; 11] = [
    "catalog",
    "relations",
    "tuples",
    "engine",
    "governance",
    "role",
    "user",
    "subject",
    "principal",
    "relation",
    "anyone",
];
/// The element id a grant has while its line is read: the id comes last on the line.
const PENDING: &str = "grant:?";
const FAILED: &str = "grant:?failed";

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Catalog,
    Relations,
    Tuples,
    Engine,
    Governance,
}

/// The heading whose lines are being read.
struct Actor {
    matcher: Option<SubjectMatcher>,
    heading: Span,
    /// Where the subject this heading declares sits in the policy, and its id.
    subject: Option<(String, Option<usize>)>,
    level: Option<u32>,
    scope: Option<Anchor>,
}

enum Ctx {
    None,
    /// The heading failed: its lines are not read again, so one mistake is one error.
    Skip,
    Section(Section),
    Actor(Actor),
}

/// What follows a heading: whether there is a line under it, and the word it starts with.
struct Below {
    child: Option<String>,
}

/// Reads every line up to the end of the file. Errors are reported on the builder and the reading
/// goes on from the next line.
pub(crate) fn parse(cur: &mut Cursor, b: &mut Builder) {
    if !cur.at_eof() && !cur.current().bol {
        b.report(Raw::new(cur.span(), "the language declaration takes its own line").hint("start a new line"));
    }
    let from = cur.index();
    let base = cur.current().span.col;
    let starts: Vec<usize> = cur.statements(None).into_iter().filter(|at| *at >= from).collect();
    let end = cur.end();
    let mut ctx = Ctx::None;
    for (n, at) in starts.iter().enumerate() {
        let fence = starts.get(n + 1).copied().unwrap_or(end);
        let below = look_below(cur, &starts, n, base, end);
        cur.goto(*at, fence);
        let col = cur.current().span.col;
        let result = if col < base {
            Err(Raw::new(cur.span(), "this line starts left of the first one").hint("headings share one column"))
        } else if col == base {
            heading(cur, b, &below).map(|next| ctx = next)
        } else {
            child(cur, b, &mut ctx, col)
        };
        match result {
            Ok(()) if cur.at_eof() => {}
            Ok(()) => {
                let token = cur.current();
                b.report(Raw::new(
                    token.span,
                    format!("unexpected {} at the end of the line", describe(&token.tok)),
                ));
            }
            Err(raw) => {
                if col <= base {
                    ctx = Ctx::Skip;
                }
                b.report(raw);
            }
        }
        cur.reset_depth();
    }
}

fn look_below(cur: &mut Cursor, starts: &[usize], n: usize, base: u32, end: usize) -> Below {
    let Some(next) = starts.get(n + 1).copied() else {
        return Below { child: None };
    };
    if cur.column_at(next) <= base {
        return Below { child: None };
    }
    cur.goto(next, (next + 1).min(end));
    let word = match cur.peek(0) {
        Tok::Ident(word) => word,
        _ => String::new(),
    };
    Below { child: Some(word) }
}

fn heading(cur: &mut Cursor, b: &mut Builder, below: &Below) -> PResult<Ctx> {
    let head = cur.current();
    let Tok::Ident(word) = head.tok.clone() else {
        return Err(Raw::new(
            head.span,
            format!("a heading starts with a word, found {}", describe(&head.tok)),
        ));
    };
    let ends = |cur: &Cursor| cur.peek(1) == Tok::Eof;
    match word.as_str() {
        "catalog" | "relations" | "tuples" | "engine" | "governance" => {
            if !ends(cur) {
                cur.advance();
                let token = cur.current();
                return Err(Raw::new(token.span, format!("`{word}` stands alone on its line")));
            }
            cur.advance();
            let section = match word.as_str() {
                "catalog" => Section::Catalog,
                "relations" => Section::Relations,
                "tuples" => Section::Tuples,
                "engine" => Section::Engine,
                _ => Section::Governance,
            };
            if section == Section::Relations && below.child.is_none() {
                empty_relations(b, head.span)?;
            }
            Ok(Ctx::Section(section))
        }
        "role" => role_heading(cur, b, head.span),
        "subject" => {
            cur.advance();
            let at = anchor(cur)?;
            let Some(sid) = at.anchor.id.clone() else {
                return Err(Raw::new(at.span, "a subject needs an id").hint("write: subject user:ana"));
            };
            let subject = declare_subject(cur, b, &at.anchor.kind, &sid, head.span);
            Ok(Ctx::Actor(Actor {
                matcher: None,
                heading: head.span,
                subject: Some(subject),
                level: None,
                scope: None,
            }))
        }
        "user" | "principal" | "relation" | "anyone" | "any" => {
            let found = matcher(cur)?;
            let declares = below
                .child
                .as_deref()
                .is_some_and(|w| matches!(w, "role" | "principal" | "attr"));
            let subject = match (&found, declares) {
                (SubjectMatcher::User { id }, true) => Some(declare_subject(cur, b, "user", id, head.span)),
                _ => None,
            };
            Ok(Ctx::Actor(Actor {
                matcher: Some(found),
                heading: head.span,
                subject,
                level: None,
                scope: None,
            }))
        }
        other => Err(Raw::new(head.span, format!("unknown heading `{other}`")).hint(suggest(other, &HEADINGS))),
    }
}

/// `relations` with nothing under it: the policy declares that it has no relations.
fn empty_relations(b: &mut Builder, at: Span) -> PResult<()> {
    let repeated = duplicate(b, ids::RELATIONS, at, "`relations`");
    b.open(ids::RELATIONS, at);
    b.close(at);
    if repeated {
        return Ok(());
    }
    if b.policy.relations.is_some() {
        let raw = Raw::new(at, "an empty `relations` comes after a relation")
            .hint("declare it before any relation, or drop it");
        b.conflict(raw, None);
        return Ok(());
    }
    b.policy.relations = Some(Vec::new());
    Ok(())
}

/// `role r [inherits a, b]` declares the role the first time; later headings of it only name it.
fn role_heading(cur: &mut Cursor, b: &mut Builder, at: Span) -> PResult<Ctx> {
    cur.advance();
    let Tok::Ident(name) = cur.peek(0) else {
        let token = cur.current();
        return Err(Raw::new(
            token.span,
            format!("expected a role name, found {}", describe(&token.tok)),
        ));
    };
    let inherits = matches!(cur.peek(1), Tok::Ident(w) if w == "inherits");
    if b.declared(&ids::role(&name)).is_some() && !inherits {
        cur.advance();
    } else {
        rules::role(cur, b)?;
    }
    Ok(Ctx::Actor(Actor {
        matcher: Some(SubjectMatcher::Role { id: name }),
        heading: at,
        subject: None,
        level: None,
        scope: None,
    }))
}

fn declare_subject(cur: &Cursor, b: &mut Builder, kind: &str, sid: &str, at: Span) -> (String, Option<usize>) {
    let id = ids::subject(kind, sid);
    let repeated = duplicate(b, &id, at, &format!("subject `{kind}:{sid}`"));
    b.open(&id, at);
    b.close(cur.previous_span());
    if repeated {
        return (id, None);
    }
    b.policy
        .subjects
        .push(Subject::of_kind(kind.to_string(), sid.to_string()));
    let at = b.policy.subjects.len() - 1;
    (id, Some(at))
}

fn child(cur: &mut Cursor, b: &mut Builder, ctx: &mut Ctx, col: u32) -> PResult<()> {
    match ctx {
        Ctx::None => {
            Err(Raw::new(cur.span(), "unexpected indentation").hint("a line under a heading, or a heading at column 1"))
        }
        Ctx::Skip => {
            while !cur.at_eof() {
                cur.advance();
            }
            Ok(())
        }
        Ctx::Section(section) => section_line(cur, b, *section),
        Ctx::Actor(actor) => {
            let level = *actor.level.get_or_insert(col);
            if col < level {
                return Err(
                    Raw::new(cur.span(), "inconsistent indentation").hint("lines under one heading share a column")
                );
            }
            if col > level {
                let Some(scope) = actor.scope.clone() else {
                    return Err(Raw::new(cur.span(), "unexpected indentation")
                        .hint("only an `in <scope>` line can have lines nested under it"));
                };
                let found = cur.current();
                return match &found.tok {
                    Tok::Ident(w) if w == "allow" || w == "deny" => grant(cur, b, actor, Some(&scope)),
                    _ => Err(Raw::new(found.span, "only rules go under an `in` line").hint("`in` blocks do not nest")),
                };
            }
            actor.scope = None;
            actor_line(cur, b, actor)
        }
    }
}

fn actor_line(cur: &mut Cursor, b: &mut Builder, actor: &mut Actor) -> PResult<()> {
    let head = cur.current();
    let Tok::Ident(word) = head.tok.clone() else {
        return Err(Raw::new(
            head.span,
            format!("a line starts with a word, found {}", describe(&head.tok)),
        ));
    };
    match word.as_str() {
        "in" => {
            cur.advance();
            actor.scope = Some(anchor(cur)?.anchor);
            Ok(())
        }
        "allow" | "deny" => grant(cur, b, actor, None),
        "role" | "principal" | "attr" => {
            let Some((id, at)) = actor.subject.clone() else {
                return Err(Raw::new(
                    head.span,
                    format!("`{word}` lines belong under a user or subject heading"),
                )
                .hint("put them first under the heading, before any rule"));
            };
            cur.advance();
            subject_line(cur, b, &word, &id, at, head.span)
        }
        other => Err(Raw::new(head.span, format!("unknown line `{other}`"))
            .hint(suggest(other, &["allow", "deny", "in", "role", "principal", "attr"]))),
    }
}

fn subject_line(cur: &mut Cursor, b: &mut Builder, word: &str, id: &str, at: Option<usize>, head: Span) -> PResult<()> {
    match word {
        "role" => {
            let role = cur.word("a role name")?;
            let assign_id = ids::assign(id, &role.v);
            let repeated = duplicate(b, &assign_id, role.span, &format!("the assignment of `{}`", role.v));
            let read = scoped(cur, b, &assign_id, head, |cur, _| assignment(cur, role.v.clone()))?;
            if !repeated {
                with_subject(b, at, |s| s.roles.push(read));
            }
        }
        "principal" => {
            let name = cur.word("a principal name")?;
            with_subject(b, at, |s| s.principals.push(name.v));
        }
        _ => {
            let key_at = cur.span();
            let read = pairs(cur)?;
            let mut clash = None;
            with_subject(b, at, |s| {
                for (key, item) in read {
                    if s.attrs.insert(key.clone(), item).is_some() {
                        clash = Some(key);
                    }
                }
            });
            if let Some(key) = clash {
                return Err(Raw::new(key_at, format!("key `{key}` is given twice")));
            }
        }
    }
    Ok(())
}

fn with_subject(b: &mut Builder, at: Option<usize>, apply: impl FnOnce(&mut Subject)) {
    if let Some(at) = at
        && let Some(subject) = b.policy.subjects.get_mut(at)
    {
        apply(subject);
    }
}

/// `allow|deny <permission> on <target> [when <c>] [from <d>] [until <d>] as <id>`
fn grant(cur: &mut Cursor, b: &mut Builder, actor: &Actor, scope: Option<&Anchor>) -> PResult<()> {
    let Some(subject) = actor.matcher.clone() else {
        return Err(
            Raw::new(cur.span(), "this heading cannot own rules").hint("use role, user, principal, relation or anyone")
        );
    };
    let effect = cur.word("allow or deny")?;
    let scope = scope.or(actor.scope.as_ref()).cloned();
    b.open(PENDING, effect.span);
    let result = grant_body(cur, b, actor, &effect.v, subject, scope);
    b.close(cur.previous_span());
    match result {
        Ok(Some(built)) => {
            b.policy.grants.push(built);
            Ok(())
        }
        Ok(None) => {
            b.rename(PENDING, FAILED);
            Ok(())
        }
        Err(raw) => {
            b.rename(PENDING, FAILED);
            Err(raw)
        }
    }
}

fn grant_body(
    cur: &mut Cursor,
    b: &mut Builder,
    actor: &Actor,
    effect: &str,
    subject: SubjectMatcher,
    scope: Option<Anchor>,
) -> PResult<Option<Grant>> {
    let permission = cur.word("a permission")?;
    if !cur.eat_word("on") {
        let token = cur.current();
        return Err(Raw::new(
            token.span,
            format!("expected `on` before the target, found {}", describe(&token.tok)),
        ));
    }
    let target_at = cur.span();
    let target = target(cur)?;
    let (mut when, mut from, mut until, mut name) = (None, None, None, None);
    let (mut when_at, mut until_at) = (None, None);
    while !cur.at_eof() {
        let clause = cur.word("when, from, until or as")?;
        let twice = || Raw::new(clause.span, format!("`{}` is given twice", clause.v));
        match clause.v.as_str() {
            "when" => {
                when_at = Some(cur.span());
                if when.replace(condition(cur)?).is_some() {
                    return Err(twice());
                }
            }
            "from" => {
                if from.replace(cur.date()?.v).is_some() {
                    return Err(twice());
                }
            }
            "until" => {
                until_at = Some(cur.span());
                if until.replace(cur.date()?.v).is_some() {
                    return Err(twice());
                }
            }
            "as" => {
                if name.replace(cur.word("a grant id")?).is_some() {
                    return Err(twice());
                }
            }
            "in" => {
                return Err(
                    Raw::new(clause.span, "a rule takes its scope from the enclosing `in` line")
                        .hint("put `in <scope>` on its own line above the rule"),
                );
            }
            other => {
                return Err(Raw::new(clause.span, format!("unexpected `{other}`"))
                    .hint("a rule takes: when <condition> from <date> until <date> as <id>"));
            }
        }
    }
    let Some(name) = name else {
        return Err(Raw::new(
            cur.span(),
            format!("a rule needs an id: end the line with `as <id>`"),
        ));
    };
    let id = ids::grant(&name.v);
    if duplicate(b, &id, name.span, &format!("grant `{}`", name.v)) {
        return Ok(None);
    }
    b.rename(PENDING, &id);
    let mark = |b: &mut Builder, field: &str, span: Span| b.mark(&ids::field(&id, field), span);
    mark(b, "subject", actor.heading);
    mark(b, "permission", permission.span);
    mark(b, "target", target_at);
    if let Some(at) = when_at {
        mark(b, "when", at);
    }
    if let Some(at) = until_at {
        mark(b, "valid_until", at);
    }
    let effect = if effect == "allow" { Effect::Allow } else { Effect::Deny };
    Ok(Some(Grant {
        id: name.v,
        subject,
        permission: permission.v,
        target,
        effect,
        scope,
        condition: when,
        valid_from: from,
        valid_until: until,
    }))
}

fn section_line(cur: &mut Cursor, b: &mut Builder, section: Section) -> PResult<()> {
    let head = cur.current();
    let word = match &head.tok {
        Tok::Ident(word) => word.clone(),
        other => {
            return Err(Raw::new(
                head.span,
                format!("a line starts with a word, found {}", describe(other)),
            ));
        }
    };
    match section {
        Section::Catalog => match word.as_str() {
            "kinds" | "broad" => {
                cur.advance();
                rules::kinds(cur, b, &head.span, word == "kinds")
            }
            _ => rules::permission(cur, b),
        },
        Section::Relations => rules::relation(cur, b),
        Section::Tuples => rules::tuple_line(cur, b),
        Section::Engine => {
            cur.advance();
            match word.as_str() {
                "strategy" => rules::strategy(cur, b, head.span),
                "depth" => rules::depth(cur, b, head.span),
                "override" => rules::override_line(cur, b),
                other => Err(Raw::new(head.span, format!("unknown engine line `{other}`"))
                    .hint(suggest(other, &["strategy", "depth", "override"]))),
            }
        }
        Section::Governance => rules::always(cur, b),
    }
}

// ---- printer --------------------------------------------------------------------------------

/// Writes the policy as an Actors source.
pub(crate) fn print(policy: &Policy) -> Printed<String> {
    let mut printer = Printer::start(policy, false)?;
    printer.leaf(0, ids::LANGUAGE, "language actors", false);
    actors(&mut printer, policy)?;
    sections(&mut printer, policy)?;
    while printer.out.ends_with("\n\n") {
        printer.out.pop();
    }
    printer.complete(policy)
}

/// How far the roles and subjects of the policy have been written: they come out in the order the
/// policy keeps them, so the reading puts them back in that order.
struct Walk<'a> {
    policy: &'a Policy,
    roles: HashMap<&'a str, usize>,
    users: HashMap<&'a str, usize>,
    next_role: usize,
    next_subject: usize,
}

fn actors(p: &mut Printer, policy: &Policy) -> Printed<()> {
    let mut walk = Walk {
        policy,
        roles: HashMap::new(),
        users: HashMap::new(),
        next_role: 0,
        next_subject: 0,
    };
    for (at, role) in policy.roles.iter().enumerate() {
        walk.roles.entry(role.role.as_str()).or_insert(at);
    }
    for (at, subject) in policy.subjects.iter().enumerate() {
        if let (true, Some(id)) = (subject.kind == "user", &subject.id) {
            walk.users.entry(id.as_str()).or_insert(at);
        }
    }
    let grants = &policy.grants;
    let mut i = 0;
    while let Some(first) = grants.get(i) {
        let mut j = i;
        while grants.get(j).is_some_and(|g| g.subject == first.subject) {
            j += 1;
        }
        p.blank();
        let decl = group_heading(p, &mut walk, &first.subject)?;
        if let Some(subject) = decl {
            decl_lines(p, subject)?;
        }
        rule_lines(p, grants.get(i..j).unwrap_or_default())?;
        i = j;
    }
    while walk.next_role < policy.roles.len() {
        lone_role(p, &mut walk)?;
    }
    while walk.next_subject < policy.subjects.len() {
        lone_subject(p, &mut walk)?;
    }
    Ok(())
}

fn lone_role(p: &mut Printer, walk: &mut Walk) -> Printed<()> {
    if let Some(role) = walk.policy.roles.get(walk.next_role) {
        let (id, text) = rules::role_text(role)?;
        p.blank();
        p.leaf(0, &id, &text, false);
    }
    walk.next_role += 1;
    Ok(())
}

fn lone_subject(p: &mut Printer, walk: &mut Walk) -> Printed<()> {
    if let Some(subject) = walk.policy.subjects.get(walk.next_subject) {
        p.blank();
        let (id, head) = subject_head(subject)?;
        p.leaf(0, &id, &head, false);
        decl_lines(p, subject)?;
    }
    walk.next_subject += 1;
    Ok(())
}

fn subject_head(s: &Subject) -> Printed<(String, String)> {
    let Some(sid) = &s.id else {
        return Err(PrintError::Unrepresentable {
            what: "a subject".to_string(),
            reason: "a subject needs an id".to_string(),
        });
    };
    let head = format!("subject {}:{}", bp::word(&s.kind, "kind")?, bp::id_part(sid, "id")?);
    Ok((ids::subject(&s.kind, sid), head))
}

fn has_decl(s: &Subject) -> bool {
    !(s.roles.is_empty() && s.principals.is_empty() && s.attrs.is_empty())
}

/// Writes the heading of a run of grants and says which subject it declares, if any.
fn group_heading<'a>(p: &mut Printer, walk: &mut Walk<'a>, m: &SubjectMatcher) -> Printed<Option<&'a Subject>> {
    match m {
        SubjectMatcher::Role { id } => {
            let at = walk.roles.get(id.as_str()).copied().filter(|at| *at >= walk.next_role);
            let Some(at) = at else {
                p.push(0, &format!("role {}", bp::word(id, "role")?));
                return Ok(None);
            };
            while walk.next_role < at {
                lone_role(p, walk)?;
                p.blank();
            }
            walk.next_role = at + 1;
            if let Some(role) = walk.policy.roles.get(at) {
                let (rid, text) = rules::role_text(role)?;
                p.leaf(0, &rid, &text, false);
            }
            Ok(None)
        }
        SubjectMatcher::User { id } => {
            let text = bp::matcher(m)?;
            let at = walk
                .users
                .get(id.as_str())
                .copied()
                .filter(|at| *at >= walk.next_subject);
            let Some(at) = at else {
                p.push(0, &text);
                return Ok(None);
            };
            while walk.next_subject < at {
                lone_subject(p, walk)?;
                p.blank();
            }
            walk.next_subject = at + 1;
            let Some(subject) = walk.policy.subjects.get(at) else {
                p.push(0, &text);
                return Ok(None);
            };
            if has_decl(subject) {
                p.leaf(0, &ids::subject("user", id), &text, false);
                return Ok(Some(subject));
            }
            let (sid, head) = subject_head(subject)?;
            p.leaf(0, &sid, &head, false);
            p.blank();
            p.push(0, &text);
            Ok(None)
        }
        other => {
            p.push(0, &bp::matcher(other)?);
            Ok(None)
        }
    }
}

fn decl_lines(p: &mut Printer, s: &Subject) -> Printed<()> {
    let Some(sid) = &s.id else {
        return Ok(());
    };
    let id = ids::subject(&s.kind, sid);
    for assignment in &s.roles {
        let role = bp::word(&assignment.role, "role")?;
        let text = format!("role {role}{}", bp::assignment_clauses(assignment)?);
        p.leaf(1, &ids::assign(&id, role), &text, false);
    }
    for principal in &s.principals {
        p.push(1, &format!("principal {}", bp::word(principal, "principal")?));
    }
    for (key, item) in &s.attrs {
        p.push(
            1,
            &format!("attr {} = {}", bp::word(key, "attribute")?, bp::value(item)?),
        );
    }
    Ok(())
}

fn rule_lines(p: &mut Printer, run: &[Grant]) -> Printed<()> {
    let mut current: Option<&Anchor> = None;
    for g in run {
        if g.scope.as_ref() != current {
            current = g.scope.as_ref();
            if let Some(scope) = current {
                p.push(1, &format!("in {}", bp::anchor(scope)?));
            }
        }
        let effect = match g.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            #[allow(unreachable_patterns, reason = "Effect may grow")]
            _ => {
                return Err(PrintError::Unrepresentable {
                    what: "a grant".to_string(),
                    reason: "the syntax does not know its effect".to_string(),
                });
            }
        };
        let name = bp::word(&g.id, "grant id")?;
        let target = bp::anchor(&Anchor {
            kind: g.target.kind.clone(),
            id: g.target.id.clone(),
        })?;
        let mut text = format!("{effect} {} on {target}", bp::word(&g.permission, "permission")?);
        if let Some(when) = &g.condition {
            text.push_str(&format!(" when {}", bp::condition(when, 0)?));
        }
        if let Some(from) = g.valid_from {
            text.push_str(&format!(" from {}", bp::date(from)?));
        }
        if let Some(until) = g.valid_until {
            text.push_str(&format!(" until {}", bp::date(until)?));
        }
        text.push_str(&format!(" as {name}"));
        p.leaf(if g.scope.is_some() { 2 } else { 1 }, &ids::grant(name), &text, false);
    }
    Ok(())
}

/// A section heading with its lines, each `(element id, text)`. A section with no line is left out.
fn block(p: &mut Printer, name: &str, lines: Vec<(String, String)>) {
    if lines.is_empty() {
        return;
    }
    p.blank();
    p.push(0, name);
    for (id, text) in lines {
        p.leaf(1, &id, &text, false);
    }
}

fn sections(p: &mut Printer, policy: &Policy) -> Printed<()> {
    let items = rules::header_items(p, policy)?;
    let (catalog, engine): (Vec<_>, Vec<_>) = items
        .into_iter()
        .partition(|(id, _)| *id == ids::TARGET_KINDS || *id == ids::BROAD_TARGETS);
    let mut lines: Vec<(String, String)> = catalog.into_iter().map(|(id, text)| (id.to_string(), text)).collect();
    for def in &policy.catalog.permissions {
        lines.push(rules::permission_text(def)?);
    }
    block(p, "catalog", lines);

    match &policy.relations {
        Some(relations) if relations.is_empty() => {
            p.blank();
            p.leaf(0, ids::RELATIONS, "relations", false);
        }
        Some(relations) => {
            let lines: Printed<Vec<_>> = relations.iter().map(rules::relation_text).collect();
            block(p, "relations", lines?);
        }
        None => {}
    }
    let tuples: Printed<Vec<_>> = policy.tuples.iter().map(rules::tuple_text).collect();
    block(p, "tuples", tuples?);

    let mut lines: Vec<(String, String)> = engine.into_iter().map(|(id, text)| (id.to_string(), text)).collect();
    for spec in &policy.overrides {
        lines.push(rules::override_text(spec)?);
    }
    block(p, "engine", lines);

    let mut ordinals = BTreeMap::new();
    let mut lines = Vec::new();
    for spec in &policy.invariants {
        lines.push(rules::invariant_text(spec, &mut ordinals)?);
    }
    block(p, "governance", lines);
    Ok(())
}
