//! The Blocks syntax: every construct is a named block of `field = value` lines. The schema is
//! the language: an unknown field is refused with a suggestion.

use std::collections::BTreeMap;

use crate::dsl::build::Builder;
use crate::dsl::error::{PResult, Raw, Span};
use crate::dsl::grammar::{
    anchor, condition, literal, matcher, path, rewrite, suggest, target, tuple, AnchorAt,
    Cursor, Sp,
};
use crate::dsl::policy::ids;
use crate::{
    Anchor, Bypass, Condition, Effect, Grant, InvariantSpec, OverrideRule, OverrideSpec,
    PermissionDef, RelationSpec, ReserveSpec, Resource, Rewrite, RoleAssignment, RoleSpec,
    StrategySpec, Subject, SubjectMatcher, TargetSelector, Value,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Words,
    Str,
    Bool,
    Word,
    Anchor,
    Anchors,
    Path,
    Date,
    Cond,
    Rewrite,
    Matcher,
    Target,
    Kv,
    Assign,
}

struct FieldSpec {
    name: &'static str,
    kind: Kind,
    required: bool,
}

const fn opt(name: &'static str, kind: Kind) -> FieldSpec {
    FieldSpec {
        name,
        kind,
        required: false,
    }
}

const fn req(name: &'static str, kind: Kind) -> FieldSpec {
    FieldSpec {
        name,
        kind,
        required: true,
    }
}

const PERMISSION: &[FieldSpec] = &[
    opt("label", Kind::Str),
    opt("description", Kind::Str),
    req("targets", Kind::Words),
    opt("implied_by", Kind::Words),
    opt("depends_on", Kind::Words),
    opt("non_delegable", Kind::Bool),
    opt("management_only", Kind::Bool),
    opt("override_only", Kind::Bool),
    opt("meta", Kind::Kv),
];
const ROLE: &[FieldSpec] = &[opt("inherits", Kind::Words)];
const SUBJECT: &[FieldSpec] = &[
    opt("principals", Kind::Words),
    opt("attrs", Kind::Kv),
    opt("assign", Kind::Assign),
];
const ASSIGN: &[FieldSpec] = &[
    opt("scope", Kind::Anchor),
    opt("valid_from", Kind::Date),
    opt("valid_until", Kind::Date),
];
const GRANT: &[FieldSpec] = &[
    req("effect", Kind::Word),
    req("subject", Kind::Matcher),
    req("permission", Kind::Word),
    req("target", Kind::Target),
    opt("scope", Kind::Anchor),
    opt("when", Kind::Cond),
    opt("valid_from", Kind::Date),
    opt("valid_until", Kind::Date),
];
const RELATION: &[FieldSpec] = &[req("rewrite", Kind::Rewrite)];
const OWNER: &[FieldSpec] = &[req("attr", Kind::Str), opt("except", Kind::Words)];
const HOLDER: &[FieldSpec] = &[req("permission", Kind::Word), opt("except", Kind::Words)];

const STRATEGIES: [&str; 4] = [
    "most_specific",
    "deny_overrides",
    "permit_overrides",
    "first_applicable",
];
const DECLARATIONS: [&str; 12] = [
    "target_kinds",
    "broad_targets",
    "strategy",
    "max_depth",
    "permission",
    "role",
    "subject",
    "grant",
    "relation",
    "tuples",
    "override",
    "invariant",
];
const INVARIANT_KINDS: [&str; 9] = [
    "catalog_conformance",
    "no_self_management",
    "prerequisites",
    "require_permission",
    "no_lockout",
    "non_delegable",
    "management_only",
    "no_escalation",
    "forbid",
];

const REQUIRE_PERMISSION: &[FieldSpec] = &[
    req("permission", Kind::Word),
    req("resource", Kind::Path),
];
const NO_LOCKOUT: &[FieldSpec] = &[
    req("permissions", Kind::Words),
    req("members", Kind::Anchors),
    req("resource", Kind::Path),
    opt("reserve_role", Kind::Word),
    opt("reserve_scope", Kind::Anchor),
    opt("reserve_subjects", Kind::Anchors),
];
const NON_DELEGABLE: &[FieldSpec] = &[req("manager", Kind::Word)];
const MANAGEMENT_ONLY: &[FieldSpec] = &[req("roles", Kind::Words)];
const NO_ESCALATION: &[FieldSpec] = &[opt("bypass", Kind::Word), opt("on", Kind::Path)];
const FORBID: &[FieldSpec] = &[
    req("subject", Kind::Matcher),
    req("permissions", Kind::Words),
];

/// The fields of one invariant kind.
fn invariant_fields(kind: &str) -> Option<&'static [FieldSpec]> {
    Some(match kind {
        "catalog_conformance" | "no_self_management" | "prerequisites" => &[],
        "require_permission" => REQUIRE_PERMISSION,
        "no_lockout" => NO_LOCKOUT,
        "non_delegable" => NON_DELEGABLE,
        "management_only" => MANAGEMENT_ONLY,
        "no_escalation" => NO_ESCALATION,
        "forbid" => FORBID,
        _ => return None,
    })
}

enum Val {
    Words(Vec<Sp<String>>),
    Str(Sp<String>),
    Bool(bool),
    Word(Sp<String>),
    Anchor(AnchorAt),
    Anchors(Vec<AnchorAt>),
    Path(Vec<AnchorAt>),
    Date(Sp<u64>),
    Cond(Condition),
    Rewrite(Rewrite),
    Matcher(SubjectMatcher),
    Target(TargetSelector),
    Kv(BTreeMap<String, Value>),
}

#[derive(Default)]
struct Body {
    fields: Vec<(&'static str, Val)>,
    assigns: Vec<(Sp<String>, Body)>,
}

macro_rules! getter {
    ($name:ident, $variant:ident, $ty:ty) => {
        fn $name(&mut self, field: &str) -> Option<$ty> {
            match self.take(field) {
                Some(Val::$variant(v)) => Some(v),
                _ => None,
            }
        }
    };
}

impl Body {
    fn has(&self, field: &str) -> bool {
        self.fields.iter().any(|(name, _)| *name == field)
    }

    fn take(&mut self, field: &str) -> Option<Val> {
        let at = self.fields.iter().position(|(name, _)| *name == field)?;
        Some(self.fields.remove(at).1)
    }

    fn words(&mut self, field: &str) -> Vec<Sp<String>> {
        self.words_opt(field).unwrap_or_default()
    }

    getter!(words_opt, Words, Vec<Sp<String>>);
    getter!(string, Str, Sp<String>);
    getter!(word, Word, Sp<String>);
    getter!(anchor, Anchor, AnchorAt);
    getter!(anchors, Anchors, Vec<AnchorAt>);
    getter!(path, Path, Vec<AnchorAt>);
    getter!(date, Date, Sp<u64>);
    getter!(cond, Cond, Condition);
    getter!(rewrite, Rewrite, Rewrite);
    getter!(matcher, Matcher, SubjectMatcher);
    getter!(target, Target, TargetSelector);
    getter!(kv, Kv, BTreeMap<String, Value>);

    fn flag(&mut self, field: &str) -> bool {
        matches!(self.take(field), Some(Val::Bool(true)))
    }
}

/// Reads every declaration up to the end of the file. Errors are reported on the builder and the
/// reading goes on from the next declaration.
pub(crate) fn parse(cur: &mut Cursor, b: &mut Builder) {
    while !cur.at_eof() {
        let start = cur.index();
        if let Err(raw) = statement(cur, b) {
            b.report(raw);
            if cur.index() == start {
                cur.advance();
            }
            while !cur.at_eof() && !at_line_start(cur) {
                cur.advance();
            }
        }
    }
}

fn at_line_start(cur: &Cursor) -> bool {
    let token = cur.current();
    token.bol && token.span.col == 1
}

fn scoped<T>(
    cur: &mut Cursor,
    b: &mut Builder,
    id: &str,
    at: Span,
    inner: impl FnOnce(&mut Cursor, &mut Builder) -> PResult<T>,
) -> PResult<T> {
    b.open(id, at);
    let result = inner(cur, b);
    b.close(cur.previous_span());
    result
}

fn duplicate(b: &mut Builder, id: &str, at: Span, what: &str) -> bool {
    match b.declared(id) {
        Some(first) => {
            let raw = Raw::new(at, format!("{what} is declared twice"))
                .hint("the first declaration is the related position");
            b.conflict(raw, Some(first));
            true
        }
        None => false,
    }
}

fn statement(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let head = cur.word("a declaration")?;
    match head.v.as_str() {
        "language" => {
            cur.word("a language name")?;
            let raw = Raw::new(head.span, "a source declares its language once, on its first line")
                .hint("one file holds one syntax: split the other into its own file");
            b.conflict(raw, b.declared(ids::LANGUAGE));
            Ok(())
        }
        "target_kinds" | "broad_targets" => kinds(cur, b, &head),
        "strategy" => strategy(cur, b, &head),
        "max_depth" => max_depth(cur, b, &head),
        "permission" => permission(cur, b),
        "role" => role(cur, b),
        "subject" => subject(cur, b),
        "grant" => grant(cur, b),
        "relation" => relation(cur, b),
        "tuples" => tuples(cur, b, &head),
        "override" => override_block(cur, b),
        "invariant" => invariant(cur, b),
        other => Err(
            Raw::new(head.span, format!("unknown declaration `{other}`"))
                .hint(suggest(other, &DECLARATIONS)),
        ),
    }
}

fn single(
    cur: &mut Cursor,
    b: &mut Builder,
    head: &Sp<String>,
    value: impl FnOnce(&mut Cursor) -> PResult<()>,
) -> PResult<()> {
    let id = head.v.as_str();
    duplicate(b, id, head.span, &format!("`{id}`"));
    scoped(cur, b, id, head.span, |cur, _| {
        cur.expect_punct("=", &format!("after `{id}`"))?;
        value(cur)
    })?;
    Ok(())
}

fn kinds(cur: &mut Cursor, b: &mut Builder, head: &Sp<String>) -> PResult<()> {
    let mut read = Vec::new();
    let repeated = b.declared(&head.v).is_some();
    single(cur, b, head, |cur| {
        read = crate::dsl::grammar::word_list(cur, "kind list")?;
        Ok(())
    })?;
    if repeated {
        return Ok(());
    }
    let names: Vec<String> = read.into_iter().map(|w| w.v).collect();
    if head.v == ids::TARGET_KINDS {
        b.policy.catalog.target_kinds = names;
    } else {
        b.policy.catalog.broad_targets = names;
    }
    Ok(())
}

fn strategy(cur: &mut Cursor, b: &mut Builder, head: &Sp<String>) -> PResult<()> {
    let repeated = b.declared(ids::STRATEGY).is_some();
    let mut chosen = StrategySpec::default();
    single(cur, b, head, |cur| {
        let word = cur.word("a strategy")?;
        chosen = match word.v.as_str() {
            "most_specific" => StrategySpec::MostSpecific,
            "deny_overrides" => StrategySpec::DenyOverrides,
            "permit_overrides" => StrategySpec::PermitOverrides,
            "first_applicable" => StrategySpec::FirstApplicable,
            other => {
                return Err(Raw::new(word.span, format!("unknown strategy `{other}`"))
                    .hint(suggest(other, &STRATEGIES)))
            }
        };
        Ok(())
    })?;
    if !repeated {
        b.policy.strategy = chosen;
    }
    Ok(())
}

fn max_depth(cur: &mut Cursor, b: &mut Builder, head: &Sp<String>) -> PResult<()> {
    let repeated = b.declared(ids::MAX_DEPTH).is_some();
    let mut depth = 0;
    single(cur, b, head, |cur| {
        depth = cur.number()?.v;
        Ok(())
    })?;
    if !repeated {
        b.policy.max_relation_depth = Some(depth);
    }
    Ok(())
}

// ---- blocks ---------------------------------------------------------------------------------

/// Reads `{ field = value ... }`, recovering at the next field after an error.
fn block_body(
    cur: &mut Cursor,
    b: &mut Builder,
    elem: &str,
    schema: &[FieldSpec],
    what: &str,
    head: &Sp<String>,
) -> PResult<Body> {
    cur.expect_punct("{", &format!("to open the {what}"))?;
    let mut body = Body::default();
    loop {
        if cur.is_punct("}") {
            cur.advance();
            break;
        }
        if cur.at_eof() {
            b.report(
                Raw::new(head.span, format!("the {what} block is not closed"))
                    .hint("add a closing `}` at the start of a line"),
            );
            break;
        }
        let start = cur.index();
        if let Err(raw) = field(cur, b, elem, schema, what, &mut body) {
            b.report(raw);
            if cur.index() == start {
                cur.advance();
            }
            while !(cur.at_eof() || cur.is_punct("}") || (cur.current().bol && is_ident(cur))) {
                cur.advance();
            }
        }
    }
    for spec in schema.iter().filter(|s| s.required) {
        if !body.has(spec.name) {
            b.report(
                Raw::new(head.span, format!("{what} `{}` needs `{}`", head.v, spec.name))
                    .hint(format!("add a line: {} = ...", spec.name)),
            );
        }
    }
    Ok(body)
}

fn is_ident(cur: &Cursor) -> bool {
    matches!(cur.current().tok, crate::dsl::lex::Tok::Ident(_))
}

fn field(
    cur: &mut Cursor,
    b: &mut Builder,
    elem: &str,
    schema: &[FieldSpec],
    what: &str,
    body: &mut Body,
) -> PResult<()> {
    let key = cur.word(&format!("a field name of the {what}"))?;
    let Some(spec) = schema.iter().find(|s| s.name == key.v) else {
        let names: Vec<&str> = schema.iter().map(|s| s.name).collect();
        return Err(
            Raw::new(key.span, format!("unknown field `{}` in {what}", key.v))
                .hint(suggest(&key.v, &names)),
        );
    };
    if spec.kind != Kind::Assign && body.has(spec.name) {
        return Err(Raw::new(key.span, format!("field `{}` is given twice in {what}", key.v))
            .hint("keep one line per field"));
    }
    let id = ids::field(elem, spec.name);
    if spec.kind == Kind::Assign {
        let role = cur.word("a role name")?;
        let assign_id = ids::assign(elem, &role.v);
        let repeated = duplicate(b, &assign_id, role.span, &format!("the assignment of `{}`", role.v));
        let inner = scoped(cur, b, &assign_id, role.span, |cur, b| {
            block_body(cur, b, &assign_id, ASSIGN, "assign", &role)
        })?;
        if !repeated {
            body.assigns.push((role, inner));
        }
        return Ok(());
    }
    let at = key.span;
    let value = scoped(cur, b, &id, at, |cur, b| {
        if spec.kind != Kind::Kv {
            cur.expect_punct("=", &format!("after `{}`", key.v))?;
        }
        value(cur, b, &id, spec.kind, &key)
    })?;
    body.fields.push((spec.name, value));
    Ok(())
}

fn value(cur: &mut Cursor, b: &mut Builder, id: &str, kind: Kind, key: &Sp<String>) -> PResult<Val> {
    Ok(match kind {
        Kind::Words => {
            let words = crate::dsl::grammar::word_list(cur, "list")?;
            for word in &words {
                b.mark(&ids::field(id, &word.v), word.span);
            }
            Val::Words(words)
        }
        Kind::Str => Val::Str(cur.string("a string")?),
        Kind::Bool => {
            let word = cur.word("true or false")?;
            match word.v.as_str() {
                "true" => Val::Bool(true),
                "false" => Val::Bool(false),
                other => {
                    return Err(Raw::new(
                        word.span,
                        format!("expected true or false, found `{other}`"),
                    ))
                }
            }
        }
        Kind::Word => Val::Word(cur.word("a name")?),
        Kind::Anchor => Val::Anchor(anchor(cur)?),
        Kind::Anchors => {
            cur.expect_punct("[", "to start the list")?;
            let mut items = Vec::new();
            while !cur.is_punct("]") {
                items.push(anchor(cur)?);
                if !cur.eat_punct(",") {
                    break;
                }
            }
            cur.expect_punct("]", "to close the list")?;
            Val::Anchors(items)
        }
        Kind::Path => Val::Path(path(cur)?),
        Kind::Date => Val::Date(cur.date()?),
        Kind::Cond => Val::Cond(condition(cur)?),
        Kind::Rewrite => Val::Rewrite(rewrite(cur)?),
        Kind::Matcher => Val::Matcher(matcher(cur)?),
        Kind::Target => Val::Target(target(cur)?),
        Kind::Kv => Val::Kv(table(cur, b, id, key)?),
        Kind::Assign => return cur.fail(key.span, "internal: assign is not a value"),
    })
}

/// `{ key = literal ... }`
fn table(
    cur: &mut Cursor,
    b: &mut Builder,
    id: &str,
    key: &Sp<String>,
) -> PResult<BTreeMap<String, Value>> {
    cur.expect_punct("{", "to open the table")?;
    let mut entries = BTreeMap::new();
    while !cur.is_punct("}") {
        if cur.at_eof() {
            return Err(Raw::new(key.span, "the table is not closed").hint("add a closing `}`"));
        }
        let name = cur.word("a key")?;
        cur.expect_punct("=", &format!("after `{}`", name.v))?;
        let item = literal(cur)?;
        b.mark(&ids::field(id, &name.v), name.span);
        if entries.insert(name.v.clone(), item).is_some() {
            return Err(Raw::new(name.span, format!("key `{}` is given twice", name.v)));
        }
    }
    cur.advance();
    Ok(entries)
}

fn names(words: Vec<Sp<String>>) -> Vec<String> {
    words.into_iter().map(|w| w.v).collect()
}

fn to_anchors(items: Vec<AnchorAt>) -> Vec<Anchor> {
    items.into_iter().map(|a| a.anchor).collect()
}

fn permission(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let key = cur.word("a permission key")?;
    let id = ids::permission(&key.v);
    let repeated = duplicate(b, &id, key.span, &format!("permission `{}`", key.v));
    let mut body = scoped(cur, b, &id, key.span, |cur, b| {
        block_body(cur, b, &id, PERMISSION, "permission", &key)
    })?;
    if repeated {
        return Ok(());
    }
    let def = PermissionDef {
        key: key.v.clone(),
        targets: names(body.words("targets")),
        label: body.string("label").map(|s| s.v),
        description: body.string("description").map(|s| s.v),
        implied_by: names(body.words("implied_by")),
        depends_on: names(body.words("depends_on")),
        non_delegable: body.flag("non_delegable"),
        management_only: body.flag("management_only"),
        override_only: body.flag("override_only"),
        meta: body.kv("meta").unwrap_or_default(),
    };
    b.policy.catalog.permissions.push(def);
    Ok(())
}

fn role(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let name = cur.word("a role name")?;
    let id = ids::role(&name.v);
    let repeated = duplicate(b, &id, name.span, &format!("role `{}`", name.v));
    let mut body = scoped(cur, b, &id, name.span, |cur, b| {
        block_body(cur, b, &id, ROLE, "role", &name)
    })?;
    if !repeated {
        b.policy.roles.push(RoleSpec {
            role: name.v,
            inherits: names(body.words("inherits")),
        });
    }
    Ok(())
}

fn subject(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let at = anchor(cur)?;
    let Some(subject_id) = at.anchor.id.clone() else {
        return Err(Raw::new(at.span, "a subject needs an id").hint("write: subject user:ana { }"));
    };
    let kind = at.anchor.kind.clone();
    let id = ids::subject(&kind, &subject_id);
    let head = Sp {
        v: format!("{kind}:{subject_id}"),
        span: at.span,
    };
    let repeated = duplicate(b, &id, at.span, &format!("subject `{}`", head.v));
    let mut body = scoped(cur, b, &id, at.span, |cur, b| {
        block_body(cur, b, &id, SUBJECT, "subject", &head)
    })?;
    if repeated {
        return Ok(());
    }
    let mut subject = Subject::of_kind(kind, subject_id);
    subject.principals = names(body.words("principals"));
    subject.attrs = body.kv("attrs").unwrap_or_default();
    for (role, mut assign) in body.assigns {
        subject.roles.push(RoleAssignment {
            role: role.v,
            scope: assign.anchor("scope").map(|a| a.anchor),
            valid_from: assign.date("valid_from").map(|d| d.v),
            valid_until: assign.date("valid_until").map(|d| d.v),
        });
    }
    b.policy.subjects.push(subject);
    Ok(())
}

fn grant(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let name = cur.word("a grant id")?;
    let id = ids::grant(&name.v);
    let repeated = duplicate(b, &id, name.span, &format!("grant `{}`", name.v));
    let mut body = scoped(cur, b, &id, name.span, |cur, b| {
        block_body(cur, b, &id, GRANT, "grant", &name)
    })?;
    if repeated {
        return Ok(());
    }
    let (Some(effect), Some(subject), Some(permission), Some(target)) = (
        body.word("effect"),
        body.matcher("subject"),
        body.word("permission"),
        body.target("target"),
    ) else {
        return Ok(());
    };
    let effect_value = match effect.v.as_str() {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        other => {
            return Err(Raw::new(
                effect.span,
                format!("effect must be allow or deny, found `{other}`"),
            ))
        }
    };
    b.policy.grants.push(Grant {
        id: name.v,
        subject,
        permission: permission.v,
        target,
        effect: effect_value,
        scope: body.anchor("scope").map(|a| a.anchor),
        condition: body.cond("when"),
        valid_from: body.date("valid_from").map(|d| d.v),
        valid_until: body.date("valid_until").map(|d| d.v),
    });
    Ok(())
}

fn relation(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let kind = cur.word("a kind")?;
    cur.expect_punct("#", "between the kind and the relation")?;
    let name = cur.word("a relation name")?;
    let id = ids::relation(&kind.v, &name.v);
    let repeated = duplicate(b, &id, kind.span, &format!("relation `{}#{}`", kind.v, name.v));
    let mut body = scoped(cur, b, &id, kind.span, |cur, b| {
        block_body(cur, b, &id, RELATION, "relation", &name)
    })?;
    if repeated {
        return Ok(());
    }
    if let Some(rewrite) = body.rewrite("rewrite") {
        b.policy
            .relations
            .get_or_insert_with(Vec::new)
            .push(RelationSpec {
                kind: kind.v,
                relation: name.v,
                rewrite,
            });
    }
    Ok(())
}

fn tuples(cur: &mut Cursor, b: &mut Builder, head: &Sp<String>) -> PResult<()> {
    scoped(cur, b, ids::TUPLES, head.span, |cur, b| {
        cur.expect_punct("{", "to open the tuple list")?;
        while !cur.is_punct("}") {
            if cur.at_eof() {
                return Err(Raw::new(head.span, "the tuples block is not closed")
                    .hint("add a closing `}`"));
            }
            let start = cur.index();
            match tuple(cur) {
                Ok((tuple, at)) => {
                    let id = ids::tuple(&tuple.to_string());
                    b.open(&id, at);
                    b.close(cur.previous_span());
                    if !b.policy.tuples.contains(&tuple) {
                        b.policy.tuples.push(tuple);
                    }
                }
                Err(raw) => {
                    b.report(raw);
                    if cur.index() == start {
                        cur.advance();
                    }
                    while !(cur.at_eof() || cur.is_punct("}") || cur.current().bol) {
                        cur.advance();
                    }
                }
            }
        }
        cur.advance();
        Ok(())
    })
}

fn override_block(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let kind = cur.word("an override kind")?;
    let (schema, what, placeholder) = match kind.v.as_str() {
        "resource_owner" => (OWNER, "resource_owner override", "override:resource_owner:"),
        "permission_holder" => (
            HOLDER,
            "permission_holder override",
            "override:permission_holder:",
        ),
        other => {
            return Err(Raw::new(kind.span, format!("unknown override `{other}`"))
                .hint(suggest(other, &["resource_owner", "permission_holder"])))
        }
    };
    let owner = kind.v == "resource_owner";
    let mut body = scoped(cur, b, placeholder, kind.span, |cur, b| {
        let body = block_body(cur, b, placeholder, schema, what, &kind)?;
        Ok(body)
    })?;
    let argument = if owner {
        body.string("attr")
    } else {
        body.word("permission")
    };
    let Some(argument) = argument else {
        return Ok(());
    };
    let id = if owner {
        ids::override_owner(&argument.v)
    } else {
        ids::override_holder(&argument.v)
    };
    // The override is named by the field of its own body, known only now.
    let first = b.declared(&id);
    b.rename(placeholder, &id);
    if let Some(first) = first {
        let raw = Raw::new(kind.span, format!("`{id}` is declared twice"));
        b.conflict(raw, Some(first));
        return Ok(());
    }
    let rule = if owner {
        OverrideRule::ResourceOwner { attr: argument.v }
    } else {
        OverrideRule::PermissionHolder {
            permission: argument.v,
        }
    };
    b.policy.overrides.push(OverrideSpec {
        rule,
        except: names(body.words("except")),
    });
    Ok(())
}

fn invariant(cur: &mut Cursor, b: &mut Builder) -> PResult<()> {
    let word = cur.word("an invariant kind")?;
    let kind = word.v.replace('-', "_");
    let Some(schema) = invariant_fields(&kind) else {
        return Err(Raw::new(word.span, format!("unknown invariant `{}`", word.v))
            .hint(suggest(&word.v, &INVARIANT_KINDS)));
    };
    let id = b.next_invariant(&kind);
    let what = format!("{kind} invariant");
    let mut body = scoped(cur, b, &id, word.span, |cur, b| {
        block_body(cur, b, &id, schema, &what, &word)
    })?;
    let spec = build_invariant(b, &kind, &word, &mut body)?;
    b.policy.invariants.push(spec);
    Ok(())
}

fn resource(path: Vec<AnchorAt>) -> Resource {
    Resource {
        path: to_anchors(path),
        attrs: BTreeMap::new(),
    }
}

fn subjects_of(items: Vec<AnchorAt>) -> PResult<Vec<Subject>> {
    items
        .into_iter()
        .map(|item| match item.anchor.id {
            Some(id) => Ok(Subject::of_kind(item.anchor.kind, id)),
            None => Err(Raw::new(item.span, "a member needs an id").hint("write kind:id")),
        })
        .collect()
}

fn build_invariant(
    b: &mut Builder,
    kind: &str,
    head: &Sp<String>,
    body: &mut Body,
) -> PResult<InvariantSpec> {
    let missing = |what: &str| Raw::new(head.span, format!("{kind} needs `{what}`"));
    Ok(match kind {
        "catalog_conformance" => InvariantSpec::CatalogConformance,
        "no_self_management" => InvariantSpec::NoSelfManagement,
        "prerequisites" => InvariantSpec::Prerequisites,
        "require_permission" => InvariantSpec::RequirePermission {
            permission: body.word("permission").ok_or_else(|| missing("permission"))?.v,
            resource: resource(body.path("resource").ok_or_else(|| missing("resource"))?),
        },
        "no_lockout" => {
            let reserve = match body.word("reserve_role") {
                Some(role) => {
                    let subjects = body.anchors("reserve_subjects").ok_or_else(|| {
                        Raw::new(role.span, "reserve_role needs `reserve_subjects`")
                            .hint("add a line: reserve_subjects = [user:ana]")
                    })?;
                    Some(ReserveSpec {
                        admin_role: RoleAssignment {
                            role: role.v,
                            scope: body.anchor("reserve_scope").map(|a| a.anchor),
                            valid_from: None,
                            valid_until: None,
                        },
                        subjects: subjects_of(subjects)?,
                    })
                }
                None => None,
            };
            InvariantSpec::NoLockout {
                permissions: names(body.words("permissions")),
                members: subjects_of(body.anchors("members").ok_or_else(|| missing("members"))?)?,
                resource: resource(body.path("resource").ok_or_else(|| missing("resource"))?),
                reserve,
            }
        }
        "non_delegable" => InvariantSpec::NonDelegable {
            manager: body.word("manager").ok_or_else(|| missing("manager"))?.v,
        },
        "management_only" => InvariantSpec::ManagementOnly {
            roles: names(body.words("roles")),
        },
        "no_escalation" => {
            let on = body.path("on");
            let bypass = match (body.word("bypass"), on) {
                (Some(permission), on) => Some(Bypass {
                    permission: permission.v,
                    resource: resource(on.unwrap_or_default()),
                }),
                (None, Some(_)) => {
                    b.report(
                        Raw::new(head.span, "`on` has no meaning without `bypass`")
                            .hint("add a line: bypass = <permission>"),
                    );
                    None
                }
                (None, None) => None,
            };
            InvariantSpec::NoEscalation { bypass }
        }
        _ => InvariantSpec::Forbid {
            subject: body.matcher("subject").ok_or_else(|| missing("subject"))?,
            permissions: names(body.words("permissions")),
        },
    })
}
