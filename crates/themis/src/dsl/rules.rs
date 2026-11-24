//! The Rules syntax: one statement per line, written to be read aloud. A line indented deeper than
//! the one above continues it.

use std::collections::{BTreeMap, HashMap};

use crate::dsl::blocks::{
    Body, STRATEGIES, build_invariant, duplicate, invariant_fields as invariant_schema, names, scoped,
    value as field_value,
};
use crate::dsl::blocks_print::{self as bp, Printer};
use crate::dsl::build::Builder;
use crate::dsl::error::{PResult, PrintError, Raw, Span};
use crate::dsl::grammar::{Cursor, Sp, condition, describe, matcher, pairs, rewrite, suggest, target, tuple};
use crate::dsl::lex::Tok;
use crate::dsl::policy::{Policy, ids};
use crate::dsl::validate::invariant_kind;
use crate::{
    Anchor, Effect, Grant, OverrideRule, OverrideSpec, PermissionDef, RelationSpec, RoleAssignment, RoleSpec,
    StrategySpec, Subject,
};

type Printed<T> = Result<T, PrintError>;

const STATEMENTS: [&str; 12] = [
    "kinds",
    "broad",
    "strategy",
    "depth",
    "permission",
    "role",
    "subject",
    "tuple",
    "relation",
    "relations",
    "override",
    "always",
];
const INVARIANT_WORDS: [&str; 9] = [
    "catalog-conformance",
    "no-self-management",
    "prerequisites",
    "require-permission",
    "no-lockout",
    "non-delegable",
    "management-only",
    "no-escalation",
    "forbid",
];
const PERMISSION_CLAUSES: [&str; 9] = [
    "implied by",
    "depends_on",
    "label",
    "about",
    "meta",
    "non-delegable",
    "management-only",
    "override-only",
    "on",
];

/// What the reading remembers between lines: where each subject sits in the policy, so a line that
/// adds to a subject finds it without a search.
#[derive(Default)]
struct State {
    subjects: HashMap<String, usize>,
}

/// Reads every statement up to the end of the file. Errors are reported on the builder and the
/// reading goes on from the next statement.
pub(crate) fn parse(cur: &mut Cursor, b: &mut Builder) {
    if !cur.at_eof() && !cur.current().bol {
        b.report(Raw::new(cur.span(), "the language declaration takes its own line").hint("start a new line"));
    }
    let from = cur.index();
    let base = cur.current().span.col;
    let starts: Vec<usize> = cur
        .statements(Some(base))
        .into_iter()
        .filter(|at| *at >= from)
        .collect();
    let end = cur.end();
    let mut state = State::default();
    for (n, at) in starts.iter().enumerate() {
        let fence = starts.get(n + 1).copied().unwrap_or(end);
        cur.goto(*at, fence);
        match statement(cur, b, &mut state) {
            Ok(()) if cur.at_eof() => {}
            Ok(()) => {
                let token = cur.current();
                b.report(Raw::new(
                    token.span,
                    format!("unexpected {} at the end of the statement", describe(&token.tok)),
                ));
            }
            Err(raw) => b.report(raw),
        }
        cur.reset_depth();
    }
}

fn statement(cur: &mut Cursor, b: &mut Builder, state: &mut State) -> PResult<()> {
    let head = cur.current();
    let Tok::Ident(word) = head.tok.clone() else {
        return Err(Raw::new(
            head.span,
            format!("a line starts with a word, found {}", describe(&head.tok)),
        ));
    };
    if cur.peek(1) == Tok::Punct(":") {
        // `g1: allow ...` is a grant, `user:ana has ...` a line about a subject.
        let word_at = |ahead: usize, text: &str| matches!(cur.peek(ahead), Tok::Ident(w) if w == text);
        let grant_like = word_at(2, "allow") || word_at(2, "deny");
        return if grant_like && !word_at(3, "has") {
            grant(cur, b)
        } else {
            subject(cur, b, state)
        };
    }
    match word.as_str() {
        "kinds" | "broad" => {
            cur.advance();
            kinds(cur, b, &head.span, word == "kinds")
        }
        "strategy" => {
            cur.advance();
            strategy(cur, b, head.span)
        }
        "depth" => {
            cur.advance();
            depth(cur, b, head.span)
        }
        "permission" => {
            cur.advance();
            permission(cur, b)
        }
        "role" => {
            cur.advance();
            role(cur, b, false)
        }
        "subject" => {
            cur.advance();
            subject(cur, b, state)
        }
        "tuple" => {
            cur.advance();
            tuple_line(cur, b)
        }
        "relation" => {
            cur.advance();
            relation(cur, b)
        }
        "relations" => {
            cur.advance();
            relations_none(cur, b, head.span)
        }
        "override" => {
            cur.advance();
            override_line(cur, b)
        }
        "always" => {
            cur.advance();
            always(cur, b)
        }
        "language" => {
            let raw = Raw::new(head.span, "a source declares its language once, on its first line")
                .hint("one file holds one syntax: split the other into its own file");
            b.conflict(raw, b.declared(ids::LANGUAGE));
            cur.advance();
            while !cur.at_eof() {
                cur.advance();
            }
            Ok(())
        }
        other => Err(Raw::new(head.span, format!("unknown statement `{other}`")).hint(suggest(other, &STATEMENTS))),
    }
}

// ---- small readers --------------------------------------------------------------------------

/// `a, b, c`
fn comma_words(cur: &mut Cursor, what: &str) -> PResult<Vec<Sp<String>>> {
    let mut items = vec![cur.word(what)?];
    while cur.eat_punct(",") {
        items.push(cur.word(what)?);
    }
    Ok(items)
}

fn expect_word(cur: &mut Cursor, word: &str, why: &str) -> PResult<()> {
    if cur.eat_word(word) {
        return Ok(());
    }
    let token = cur.current();
    Err(Raw::new(
        token.span,
        format!("expected `{word}` {why}, found {}", describe(&token.tok)),
    ))
}

fn twice<T>(slot: &mut Option<T>, clause: &Sp<String>, value: T) -> PResult<()> {
    if slot.replace(value).is_some() {
        return Err(Raw::new(clause.span, format!("`{}` is given twice", clause.v)));
    }
    Ok(())
}

/// A word list whose items are marked under `id/field`, where the validator looks them up.
fn marked_words(cur: &mut Cursor, b: &mut Builder, id: &str, field: &str, what: &str) -> PResult<Vec<String>> {
    let list = comma_words(cur, what)?;
    let under = ids::field(id, field);
    for word in &list {
        b.mark(&ids::field(&under, &word.v), word.span);
    }
    Ok(names(list))
}

fn mark(b: &mut Builder, id: &str, field: &str, span: Span) {
    b.mark(&ids::field(id, field), span);
}

// ---- header ---------------------------------------------------------------------------------

pub(crate) fn kinds(cur: &mut Cursor, b: &mut Builder, at: &Span, target_kinds: bool) -> PResult<()> {
    let id = if target_kinds {
        ids::TARGET_KINDS
    } else {
        ids::BROAD_TARGETS
    };
    let repeated = duplicate(b, id, *at, &format!("`{id}`"));
    let list = scoped(cur, b, id, *at, |cur, _| comma_words(cur, "a kind"))?;
    if !repeated {
        let list = names(list);
        if target_kinds {
            b.policy.catalog.target_kinds = list;
        } else {
            b.policy.catalog.broad_targets = list;
        }
    }
    Ok(())
}

pub(crate) fn strategy(cur: &mut Cursor, b: &mut Builder, at: Span) -> PResult<()> {
    let repeated = duplicate(b, ids::STRATEGY, at, "`strategy`");
    let chosen = scoped(cur, b, ids::STRATEGY, at, |cur, _| {
        let word = cur.word("a strategy")?;
        Ok(match word.v.as_str() {
            "most_specific" => StrategySpec::MostSpecific,
            "deny_overrides" => StrategySpec::DenyOverrides,
            "permit_overrides" => StrategySpec::PermitOverrides,
            "first_applicable" => StrategySpec::FirstApplicable,
            other => {
                return Err(
                    Raw::new(word.span, format!("unknown strategy `{other}`")).hint(suggest(other, &STRATEGIES))
                );
            }
        })
    })?;
    if !repeated {
        b.policy.strategy = chosen;
    }
    Ok(())
}

pub(crate) fn depth(cur: &mut Cursor, b: &mut Builder, at: Span) -> PResult<()> {
    let repeated = duplicate(b, ids::MAX_DEPTH, at, "`depth`");
    let found = scoped(cur, b, ids::MAX_DEPTH, at, |cur, _| Ok(cur.number()?.v))?;
    if !repeated {
        b.policy.max_relation_depth = Some(found);
    }
    Ok(())
}

// ---- catalog, roles, subjects ---------------------------------------------------------------

pub(crate) fn permission(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let key = cur.word("a permission key")?;
    let id = ids::permission(&key.v);
    let repeated = duplicate(b, &id, key.span, &format!("permission `{}`", key.v));
    let def = scoped(cur, b, &id, key.span, |cur, b| {
        let mut def = PermissionDef::new(key.v.clone());
        expect_word(cur, "on", "after the permission key, then the kinds it applies to")?;
        def.targets = marked_words(cur, b, &id, "targets", "a target kind")?;
        let (mut implied, mut depends_on, mut label, mut about, mut meta) = (None, None, None, None, None);
        while !cur.at_eof() {
            let clause = cur.word("a clause")?;
            match clause.v.as_str() {
                "implied" => {
                    expect_word(cur, "by", "after `implied`")?;
                    let list = marked_words(cur, b, &id, "implied_by", "a permission")?;
                    twice(&mut implied, &clause, list)?;
                }
                "depends_on" => {
                    let list = marked_words(cur, b, &id, "depends_on", "a permission")?;
                    twice(&mut depends_on, &clause, list)?;
                }
                "needs" => {
                    return Err(Raw::new(clause.span, "`needs` is now `depends_on`").hint("write: depends_on <ids>"));
                }
                "label" => twice(&mut label, &clause, cur.string("the label")?.v)?,
                "about" => twice(&mut about, &clause, cur.string("the description")?.v)?,
                "meta" => twice(&mut meta, &clause, pairs(cur)?)?,
                "non-delegable" => def.non_delegable = true,
                "management-only" => def.management_only = true,
                "override-only" => def.override_only = true,
                other => {
                    return Err(Raw::new(clause.span, format!("unknown clause `{other}`"))
                        .hint(suggest(other, &PERMISSION_CLAUSES)));
                }
            }
        }
        def.implied_by = implied.unwrap_or_default();
        def.depends_on = depends_on.unwrap_or_default();
        def.label = label;
        def.description = about;
        def.meta = meta.unwrap_or_default();
        Ok(def)
    })?;
    if !repeated {
        b.policy.catalog.permissions.push(def);
    }
    Ok(())
}

/// `empty_inherits` lets a bare `inherits` end the line: the Actors spelling of a role whose name
/// is close to a declared one but is meant as new.
pub(crate) fn role(cur: &mut Cursor, b: &mut Builder, empty_inherits: bool) -> PResult<()> {
    let name = cur.word("a role name")?;
    let id = ids::role(&name.v);
    let repeated = duplicate(b, &id, name.span, &format!("role `{}`", name.v));
    let inherits = scoped(cur, b, &id, name.span, |cur, _| {
        if cur.eat_word("inherits") {
            if empty_inherits && cur.at_eof() {
                return Ok(Vec::new());
            }
            Ok(names(comma_words(cur, "a role")?))
        } else {
            Ok(Vec::new())
        }
    })?;
    if !repeated {
        b.policy.roles.push(RoleSpec { role: name.v, inherits });
    }
    Ok(())
}

/// `subject user:ana`, or `user:ana has role r in s from d until d`, `has principal p`,
/// `has attr k = v`. Every line adds to the subject; the first one makes it.
fn subject(cur: &mut Cursor, b: &mut Builder, state: &mut State) -> PResult<()> {
    let at = crate::dsl::grammar::anchor(cur)?;
    let Some(sid) = at.anchor.id.clone() else {
        return Err(Raw::new(at.span, "a subject needs an id").hint("write: subject user:ana"));
    };
    let kind = at.anchor.kind.clone();
    let id = ids::subject(&kind, &sid);
    let first = b.declared(&id).is_none();
    let bare = cur.at_eof();
    if bare {
        let repeated = duplicate(b, &id, at.span, &format!("subject `{kind}:{sid}`"));
        scoped(cur, b, &id, at.span, |_, _| Ok(()))?;
        if !repeated {
            add_subject(b, state, &id, Subject::of_kind(kind, sid));
        }
        return Ok(());
    }
    expect_word(cur, "has", &format!("after `{kind}:{sid}`"))?;
    let clause = cur.word("role, principal or attr")?;
    // The first line of a subject stands for the subject; a later role line is its assignment.
    let extent = |role: Option<&str>| match role {
        Some(role) if !first => ids::assign(&id, role),
        _ => id.clone(),
    };
    match clause.v.as_str() {
        "role" => {
            let role = cur.word("a role name")?;
            let assign_id = ids::assign(&id, &role.v);
            let repeated = duplicate(b, &assign_id, role.span, &format!("the assignment of `{}`", role.v));
            let extent_id = extent(Some(&role.v));
            let read = scoped(cur, b, &extent_id, at.span, |cur, b| {
                if first {
                    b.mark(&assign_id, role.span);
                }
                let read = crate::dsl::grammar::assignment(cur, role.v.clone())?;
                Ok(read)
            })?;
            if !repeated {
                let assignment: RoleAssignment = read;
                add_line(b, state, &id, first, &kind, &sid, |s| s.roles.push(assignment));
            }
        }
        "principal" => {
            let extent_id = extent(None);
            let name = scoped(cur, b, &extent_id, at.span, |cur, _| cur.word("a principal name"))?;
            add_line(b, state, &id, first, &kind, &sid, |s| s.principals.push(name.v));
        }
        "attr" => {
            let extent_id = extent(None);
            let key_at = cur.span();
            let read = scoped(cur, b, &extent_id, at.span, |cur, _| pairs(cur))?;
            let mut clash = None;
            add_line(b, state, &id, first, &kind, &sid, |s| {
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
        other => {
            return Err(Raw::new(
                clause.span,
                format!("a subject can have a role, principal or attr, not `{other}`"),
            ));
        }
    }
    Ok(())
}

fn add_subject(b: &mut Builder, state: &mut State, id: &str, subject: Subject) {
    state.subjects.insert(id.to_string(), b.policy.subjects.len());
    b.policy.subjects.push(subject);
}

/// Applies a line to its subject, creating the subject when the line is its first.
fn add_line(
    b: &mut Builder,
    state: &mut State,
    id: &str,
    first: bool,
    kind: &str,
    sid: &str,
    apply: impl FnOnce(&mut Subject),
) {
    if first {
        add_subject(b, state, id, Subject::of_kind(kind.to_string(), sid.to_string()));
    }
    if let Some(at) = state.subjects.get(id).copied()
        && let Some(subject) = b.policy.subjects.get_mut(at)
    {
        apply(subject);
    }
}

// ---- grants ---------------------------------------------------------------------------------

fn grant(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let name = cur.word("a grant id")?;
    cur.expect_punct(":", "after the grant id")?;
    let effect = cur.word("allow or deny")?;
    let effect_value = match effect.v.as_str() {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        other => {
            return Err(Raw::new(
                effect.span,
                format!("effect must be allow or deny, found `{other}`"),
            ));
        }
    };
    let id = ids::grant(&name.v);
    let repeated = duplicate(b, &id, name.span, &format!("grant `{}`", name.v));
    let built = scoped(cur, b, &id, name.span, |cur, b| {
        let subject_at = cur.span();
        let subject = matcher(cur)?;
        mark(b, &id, "subject", subject_at);
        expect_word(cur, "to", "before the permission")?;
        let permission = cur.word("a permission")?;
        mark(b, &id, "permission", permission.span);
        expect_word(cur, "on", "before the target")?;
        let target_at = cur.span();
        let target = target(cur)?;
        mark(b, &id, "target", target_at);
        let (mut scope, mut when, mut from, mut until) = (None, None, None, None);
        while !cur.at_eof() {
            let clause = cur.word("in, when, from or until")?;
            match clause.v.as_str() {
                "in" => twice(&mut scope, &clause, crate::dsl::grammar::anchor(cur)?.anchor)?,
                "when" => {
                    mark(b, &id, "when", cur.span());
                    twice(&mut when, &clause, condition(cur)?)?;
                }
                "from" => twice(&mut from, &clause, cur.date()?.v)?,
                "until" => {
                    mark(b, &id, "valid_until", cur.span());
                    twice(&mut until, &clause, cur.date()?.v)?;
                }
                other => {
                    return Err(Raw::new(clause.span, format!("unexpected `{other}`"))
                        .hint("a grant takes: in <scope> when <condition> from <date> until <date>"));
                }
            }
        }
        Ok(Grant {
            id: name.v.clone(),
            subject,
            permission: permission.v,
            target,
            effect: effect_value,
            scope,
            condition: when,
            valid_from: from,
            valid_until: until,
        })
    })?;
    if !repeated {
        b.policy.grants.push(built);
    }
    Ok(())
}

// ---- relations, tuples, overrides, invariants -----------------------------------------------

/// `relations none`: the policy declares that it has no relations, as opposed to saying nothing.
fn relations_none(cur: &mut Cursor, b: &mut Builder, at: Span) -> PResult<()> {
    let repeated = duplicate(b, ids::RELATIONS, at, "`relations`");
    scoped(cur, b, ids::RELATIONS, at, |cur, _| {
        expect_word(cur, "none", "after `relations`: it only takes `none`")
    })?;
    if repeated {
        return Ok(());
    }
    if b.policy.relations.is_some() {
        let raw =
            Raw::new(at, "`relations none` comes after a relation").hint("declare it before any relation, or drop it");
        b.conflict(raw, None);
        return Ok(());
    }
    b.policy.relations = Some(Vec::new());
    Ok(())
}

pub(crate) fn relation(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let kind = cur.word("a kind")?;
    cur.expect_punct("#", "between the kind and the relation")?;
    let name = cur.word("a relation name")?;
    let id = ids::relation(&kind.v, &name.v);
    let repeated = duplicate(b, &id, kind.span, &format!("relation `{}#{}`", kind.v, name.v));
    let read = scoped(cur, b, &id, kind.span, |cur, _| {
        cur.expect_punct("=", "before the rewrite")?;
        rewrite(cur)
    })?;
    if repeated {
        return Ok(());
    }
    if let Some(first) = b.declared(ids::RELATIONS) {
        let raw = Raw::new(kind.span, "a relation follows `relations none`").hint("drop `relations none`");
        b.conflict(raw, Some(first));
        return Ok(());
    }
    b.policy.relations.get_or_insert_with(Vec::new).push(RelationSpec {
        kind: kind.v,
        relation: name.v,
        rewrite: read,
    });
    Ok(())
}

pub(crate) fn tuple_line(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let (tuple, at) = tuple(cur)?;
    let id = ids::tuple(&tuple.to_string());
    let repeated = duplicate(b, &id, at, &format!("the tuple `{tuple}`"));
    b.open(&id, at);
    b.close(cur.previous_span());
    if !repeated {
        b.policy.tuples.push(tuple);
    }
    Ok(())
}

pub(crate) fn override_line(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let kind = cur.word("an override kind")?;
    let owner = match kind.v.replace('-', "_").as_str() {
        "resource_owner" => true,
        "permission_holder" => false,
        other => {
            return Err(Raw::new(kind.span, format!("unknown override `{other}`"))
                .hint(suggest(other, &["resource-owner", "permission-holder"])));
        }
    };
    let argument = if owner {
        // A plain word, or a string for a path a word cannot hold.
        if matches!(cur.current().tok, Tok::Str(_)) {
            cur.string("the owner attribute")?
        } else {
            cur.word("the owner attribute")?
        }
    } else {
        cur.word("a permission")?
    };
    let id = if owner {
        ids::override_owner(&argument.v)
    } else {
        ids::override_holder(&argument.v)
    };
    let repeated = duplicate(b, &id, kind.span, &format!("`{id}`"));
    let except = scoped(cur, b, &id, kind.span, |cur, _| {
        if cur.eat_word("except") {
            Ok(names(comma_words(cur, "a permission")?))
        } else {
            Ok(Vec::new())
        }
    })?;
    if !repeated {
        let rule = if owner {
            OverrideRule::ResourceOwner { attr: argument.v }
        } else {
            OverrideRule::PermissionHolder { permission: argument.v }
        };
        b.policy.overrides.push(OverrideSpec { rule, except });
    }
    Ok(())
}

/// `always <kind> name value name value`: the names are the fields of the invariant.
pub(crate) fn always(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let word = cur.word("an invariant kind")?;
    let kind = word.v.replace('-', "_");
    let Some(schema) = invariant_schema(&kind) else {
        return Err(Raw::new(word.span, format!("unknown invariant `{}`", word.v))
            .hint(suggest(&word.v.replace('_', "-"), &INVARIANT_WORDS)));
    };
    let id = b.next_invariant(&kind);
    let spec = scoped(cur, b, &id, word.span, |cur, b| {
        let mut body = Body::default();
        while !cur.at_eof() {
            let key = cur.word("a field of the invariant")?;
            let Some(spec) = schema.iter().find(|s| s.name == key.v) else {
                let known: Vec<&str> = schema.iter().map(|s| s.name).collect();
                return Err(
                    Raw::new(key.span, format!("unknown field `{}` in {kind} invariant", key.v))
                        .hint(suggest(&key.v, &known)),
                );
            };
            if body.has(spec.name) {
                return Err(Raw::new(key.span, format!("field `{}` is given twice", key.v)));
            }
            let field_id = ids::field(&id, spec.name);
            let read = field_value(cur, b, &field_id, spec.kind, &key)?;
            b.mark(&field_id, key.span);
            body.fields.push((spec.name, read));
        }
        for needed in schema.iter().filter(|s| s.required) {
            if !body.has(needed.name) {
                return Err(Raw::new(word.span, format!("{kind} needs `{}`", needed.name))
                    .hint(format!("add: {} <value>", needed.name)));
            }
        }
        build_invariant(b, &kind, &word, &mut body)
    })?;
    b.policy.invariants.push(spec);
    Ok(())
}

// ---- printer --------------------------------------------------------------------------------

/// Writes the policy as a Rules source.
pub(crate) fn print(policy: &Policy) -> Printed<String> {
    let mut printer = Printer::start(policy, false)?;
    lines(&mut printer, policy)?;
    while printer.out.ends_with("\n\n") {
        printer.out.pop();
    }
    printer.complete(policy)
}

pub(crate) fn list(items: &[String], what: &str) -> Printed<String> {
    if items.is_empty() {
        return Err(PrintError::Unrepresentable {
            what: format!("an empty list of {what}s"),
            reason: "the syntax has no spelling for it".to_string(),
        });
    }
    let parts: Printed<Vec<&str>> = items.iter().map(|item| bp::word(item, what)).collect();
    Ok(parts?.join(", "))
}

pub(crate) fn strategy_word(s: StrategySpec) -> Printed<&'static str> {
    Ok(match s {
        StrategySpec::MostSpecific => "most_specific",
        StrategySpec::DenyOverrides => "deny_overrides",
        StrategySpec::PermitOverrides => "permit_overrides",
        StrategySpec::FirstApplicable => "first_applicable",
        #[allow(unreachable_patterns, reason = "StrategySpec may grow")]
        _ => {
            return Err(PrintError::Unrepresentable {
                what: "the strategy".to_string(),
                reason: "the syntax does not know it".to_string(),
            });
        }
    })
}

fn lines(p: &mut Printer, policy: &Policy) -> Printed<()> {
    p.leaf(0, ids::LANGUAGE, "language rules", false);
    let found = header_items(p, policy)?;
    if !found.is_empty() {
        p.blank();
        for (id, text) in found {
            p.leaf(0, id, &text, false);
        }
    }
    let mut section = Section::default();
    for def in &policy.catalog.permissions {
        section.start(p);
        let (id, head, clauses) = permission_parts(def)?;
        p.leaf(0, &id, &wrap_clauses(&format!("permission {head}"), &clauses), false);
    }
    section = Section::default();
    for role in &policy.roles {
        section.start(p);
        let (id, text) = role_text(role)?;
        p.leaf(0, &id, &text, false);
    }
    section = Section::default();
    for subject in &policy.subjects {
        section.start(p);
        subject_lines(p, subject)?;
    }
    section = Section::default();
    for grant in &policy.grants {
        section.start(p);
        grant_line(p, grant)?;
    }
    section = Section::default();
    if let Some(relations) = &policy.relations {
        if relations.is_empty() {
            section.start(p);
            p.leaf(0, ids::RELATIONS, "relations none", false);
        }
        for relation in relations {
            section.start(p);
            let (id, text) = relation_text(relation)?;
            p.leaf(0, &id, &format!("relation {text}"), false);
        }
    }
    section = Section::default();
    for tuple in &policy.tuples {
        section.start(p);
        let (id, text) = tuple_text(tuple)?;
        p.leaf(0, &id, &format!("tuple {text}"), false);
    }
    section = Section::default();
    for spec in &policy.overrides {
        section.start(p);
        let (id, text) = override_text(spec)?;
        p.leaf(0, &id, &text, false);
    }
    let mut ordinals = BTreeMap::new();
    for spec in &policy.invariants {
        section.start(p);
        let (id, text) = invariant_text(spec, &mut ordinals)?;
        p.leaf(0, &id, &format!("always {text}"), false);
    }
    Ok(())
}

pub(crate) fn role_text(role: &RoleSpec) -> Printed<(String, String)> {
    let name = bp::word(&role.role, "role")?;
    let text = if role.inherits.is_empty() {
        format!("role {name}")
    } else {
        format!("role {name} inherits {}", list(&role.inherits, "role")?)
    };
    Ok((ids::role(name), text))
}

pub(crate) fn relation_text(relation: &RelationSpec) -> Printed<(String, String)> {
    let kind = bp::word(&relation.kind, "kind")?;
    let name = bp::word(&relation.relation, "relation")?;
    let text = format!("{kind}#{name} = {}", bp::rewrite(&relation.rewrite, true)?);
    Ok((ids::relation(kind, name), text))
}

/// `kind field value ...`, numbering the invariants of each kind as the reading does.
pub(crate) fn invariant_text(
    spec: &crate::InvariantSpec,
    ordinals: &mut BTreeMap<&'static str, usize>,
) -> Printed<(String, String)> {
    let kind = invariant_kind(spec);
    let ordinal = ordinals.entry(kind).or_insert(0);
    *ordinal += 1;
    let mut text = kind.replace('_', "-");
    for (name, value) in bp::invariant_fields(spec)? {
        text.push_str(&format!(" {name} {value}"));
    }
    Ok((ids::invariant(kind, *ordinal), text))
}

/// A run of lines of one kind: a blank line comes before the first.
#[derive(Default)]
struct Section {
    started: bool,
}

impl Section {
    fn start(&mut self, p: &mut Printer) {
        if !self.started {
            self.started = true;
            p.blank();
        }
    }
}

/// The lines of the header (kinds, broad, strategy, depth) that the policy needs, with their ids.
pub(crate) fn header_items(p: &Printer, policy: &Policy) -> Printed<Vec<(&'static str, String)>> {
    let mut found: Vec<(&'static str, String)> = Vec::new();
    for (id, word, items) in [
        (ids::TARGET_KINDS, "kinds", &policy.catalog.target_kinds),
        (ids::BROAD_TARGETS, "broad", &policy.catalog.broad_targets),
    ] {
        if !items.is_empty() {
            found.push((id, format!("{word} {}", list(items, "kind")?)));
        } else if p.has_notes(id) {
            return Err(PrintError::Unrepresentable {
                what: format!("a comment on `{id}`"),
                reason: "the list is empty, so there is no line to put it on".to_string(),
            });
        }
    }
    if policy.strategy != StrategySpec::default() || p.has_notes(ids::STRATEGY) {
        found.push((ids::STRATEGY, format!("strategy {}", strategy_word(policy.strategy)?)));
    }
    match policy.max_relation_depth {
        Some(depth) => found.push((ids::MAX_DEPTH, format!("depth {depth}"))),
        None if p.has_notes(ids::MAX_DEPTH) => {
            return Err(PrintError::Unrepresentable {
                what: "a comment on `max_depth`".to_string(),
                reason: "the policy sets no maximum depth".to_string(),
            });
        }
        None => {}
    }
    Ok(found)
}

/// The longest a line of a printed rule gets before its clauses move to continuation lines.
const LINE_WIDTH: usize = 100;

/// `head clause clause ...` on one line when it fits, otherwise the clauses one per line,
/// indented four spaces under the head.
fn wrap_clauses(head: &str, clauses: &[String]) -> String {
    let one = std::iter::once(head)
        .chain(clauses.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    if one.chars().count() <= LINE_WIDTH || clauses.is_empty() {
        return one;
    }
    let mut text = head.to_string();
    for clause in clauses {
        text.push_str("\n    ");
        text.push_str(clause);
    }
    text
}

/// The pieces of a permission line: its id, what comes before the clauses, and the clauses in the
/// order `implied by`, `depends_on`, `label`, `about`, `meta`, then the flags.
fn permission_parts(def: &PermissionDef) -> Printed<(String, String, Vec<String>)> {
    let key = bp::word(&def.key, "permission key")?;
    let head = format!("{key} on {}", list(&def.targets, "kind")?);
    let mut clauses = Vec::new();
    if !def.implied_by.is_empty() {
        clauses.push(format!("implied by {}", list(&def.implied_by, "permission")?));
    }
    if !def.depends_on.is_empty() {
        clauses.push(format!("depends_on {}", list(&def.depends_on, "permission")?));
    }
    if let Some(label) = &def.label {
        clauses.push(format!("label {}", bp::quote(label)));
    }
    if let Some(about) = &def.description {
        clauses.push(format!("about {}", bp::quote(about)));
    }
    if !def.meta.is_empty() {
        clauses.push(format!("meta {}", bp::pairs(&def.meta)?));
    }
    for (word, on) in [
        ("non-delegable", def.non_delegable),
        ("management-only", def.management_only),
        ("override-only", def.override_only),
    ] {
        if on {
            clauses.push(word.to_string());
        }
    }
    Ok((ids::permission(key), head, clauses))
}

pub(crate) fn permission_text(def: &PermissionDef) -> Printed<(String, String)> {
    let (id, head, clauses) = permission_parts(def)?;
    Ok((id, std::iter::once(head).chain(clauses).collect::<Vec<_>>().join(" ")))
}

fn subject_lines(p: &mut Printer, s: &Subject) -> Printed<()> {
    let Some(sid) = &s.id else {
        return Err(PrintError::Unrepresentable {
            what: "a subject".to_string(),
            reason: "a subject needs an id".to_string(),
        });
    };
    let head = format!("{}:{}", bp::word(&s.kind, "kind")?, bp::id_part(sid, "id")?);
    let id = ids::subject(&s.kind, sid);
    let mut lines: Vec<(Option<String>, String)> = Vec::new();
    for assignment in &s.roles {
        let role = bp::word(&assignment.role, "role")?;
        let text = format!("{head} has role {role}{}", bp::assignment_clauses(assignment)?);
        lines.push((Some(ids::assign(&id, role)), text));
    }
    for principal in &s.principals {
        lines.push((
            None,
            format!("{head} has principal {}", bp::word(principal, "principal")?),
        ));
    }
    for (key, item) in &s.attrs {
        let key = bp::word(key, "attribute")?;
        lines.push((None, format!("{head} has attr {key} = {}", bp::value(item)?)));
    }
    // The first line stands for the subject. A role line with comments of its own cannot be it.
    let bare = match lines.first() {
        None => true,
        Some((Some(assign), _)) => p.has_notes(assign),
        Some((None, _)) => false,
    };
    if bare {
        p.leaf(0, &id, &format!("subject {head}"), false);
    }
    for (at, (assign, text)) in lines.iter().enumerate() {
        match assign {
            _ if at == 0 && !bare => p.leaf(0, &id, text, false),
            Some(assign) => p.leaf(0, assign, text, false),
            None => p.push(0, text),
        }
    }
    Ok(())
}

fn grant_line(p: &mut Printer, g: &Grant) -> Printed<()> {
    let name = bp::word(&g.id, "grant id")?;
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
    let target = bp::anchor(&Anchor {
        kind: g.target.kind.clone(),
        id: g.target.id.clone(),
    })?;
    let head = format!(
        "{name}: {effect} {} to {} on {target}",
        bp::matcher(&g.subject)?,
        bp::word(&g.permission, "permission")?
    );
    let mut clauses = Vec::new();
    if let Some(scope) = &g.scope {
        clauses.push(format!("in {}", bp::anchor(scope)?));
    }
    if let Some(when) = &g.condition {
        clauses.push(format!("when {}", bp::condition(when, 0)?));
    }
    if let Some(from) = g.valid_from {
        clauses.push(format!("from {}", bp::date(from)?));
    }
    if let Some(until) = g.valid_until {
        clauses.push(format!("until {}", bp::date(until)?));
    }
    p.leaf(0, &ids::grant(name), &wrap_clauses(&head, &clauses), false);
    Ok(())
}

pub(crate) fn tuple_text(tuple: &crate::Tuple) -> Printed<(String, String)> {
    use crate::TupleSubject;
    bp::word(&tuple.object.kind, "tuple kind")?;
    bp::id_part(&tuple.object.id, "tuple id")?;
    bp::word(&tuple.relation, "tuple relation")?;
    let (subject, set) = match &tuple.subject {
        TupleSubject::Object(object) => (object, None),
        TupleSubject::Userset(object, relation) => (object, Some(relation)),
        #[allow(unreachable_patterns, reason = "TupleSubject may grow")]
        _ => {
            return Err(PrintError::Unrepresentable {
                what: "a tuple".to_string(),
                reason: "the syntax does not know its subject".to_string(),
            });
        }
    };
    bp::word(&subject.kind, "tuple subject kind")?;
    bp::id_part(&subject.id, "tuple subject id")?;
    if let Some(relation) = set {
        bp::word(relation, "tuple subject relation")?;
    }
    let text = tuple.to_string();
    Ok((ids::tuple(&text), text))
}

pub(crate) fn override_text(spec: &OverrideSpec) -> Printed<(String, String)> {
    let (id, mut text) = match &spec.rule {
        OverrideRule::ResourceOwner { attr } => (
            ids::override_owner(attr),
            format!(
                "override resource-owner {}",
                bp::word(attr, "owner attribute").map_or_else(|_| bp::quote(attr), str::to_string)
            ),
        ),
        OverrideRule::PermissionHolder { permission } => (
            ids::override_holder(permission),
            format!("override permission-holder {}", bp::word(permission, "permission")?),
        ),
        #[allow(unreachable_patterns, reason = "OverrideRule may grow")]
        _ => {
            return Err(PrintError::Unrepresentable {
                what: "an override".to_string(),
                reason: "the syntax does not know it".to_string(),
            });
        }
    };
    if !spec.except.is_empty() {
        text.push_str(&format!(" except {}", list(&spec.except, "permission")?));
    }
    Ok((id, text))
}
