//! The Blocks printer: the inverse of the parser. A policy printed here reads back as the same
//! policy with the same comments on the same elements.

use std::collections::BTreeMap;

use crate::dsl::error::PrintError;
use crate::dsl::lex::{Tok, lex};
use crate::dsl::policy::{Placement, Policy, ids};
use crate::dsl::time;
use crate::dsl::validate::{invariant_kind, is_attr_path};
use crate::{
    Anchor, Condition, Effect, InvariantSpec, Operand, OverrideRule, Resource, Rewrite, StrategySpec, Subject,
    SubjectMatcher, TupleSubject, Value,
};

type Printed<T> = Result<T, PrintError>;

fn unrepresentable<T>(what: impl Into<String>, reason: impl Into<String>) -> Printed<T> {
    Err(PrintError::Unrepresentable {
        what: what.into(),
        reason: reason.into(),
    })
}

#[derive(Default)]
struct Slots {
    before: Vec<String>,
    after: Vec<String>,
    inline: Vec<String>,
}

struct Printer {
    out: String,
    notes: BTreeMap<String, Slots>,
}

/// Writes the policy as a Blocks source.
pub(crate) fn print(policy: &Policy) -> Printed<String> {
    let mut notes: BTreeMap<String, Slots> = BTreeMap::new();
    for note in &policy.notes {
        if note.text.contains('\n') || note.text.contains('\r') {
            return unrepresentable("a note", "a comment holds one line");
        }
        // A comment written next to a field goes back next to it; the anchor stays the element.
        let key = match &note.origin.field {
            Some(field) => ids::field(&note.anchor.element, field),
            None => note.anchor.element.clone(),
        };
        let slots = notes.entry(key).or_default();
        match note.anchor.placement {
            Placement::Before => slots.before.push(note.text.clone()),
            Placement::After => slots.after.push(note.text.clone()),
            Placement::Inline => slots.inline.push(note.text.clone()),
            #[allow(unreachable_patterns, reason = "Placement is non_exhaustive")]
            _ => slots.before.push(note.text.clone()),
        }
    }
    if let Some(key) = notes.iter().find(|(_, slots)| slots.inline.len() > 1).map(|(key, _)| key) {
        return unrepresentable(
            format!("the comments of `{key}`"),
            "two comments on the same line have no spelling",
        );
    }
    let mut printer = Printer {
        out: String::new(),
        notes,
    };
    printer.policy(policy)?;
    printer.orphans()?;
    printer.check_round_trip(policy)?;
    Ok(printer.out)
}

// ---- checks on what is written ---------------------------------------------------------------

/// A name the lexer reads back as one word.
fn word<'a>(text: &'a str, what: &str) -> Printed<&'a str> {
    let lexed = lex(text);
    match lexed.tokens.as_slice() {
        [first, last] if matches!(&first.tok, Tok::Ident(v) if v == text) && last.tok == Tok::Eof => Ok(text),
        _ => unrepresentable(
            format!("{what} `{text}`"),
            "it is not a name the language can read back",
        ),
    }
}

/// The id after `:`: a word, a number or `*`.
fn id_part<'a>(text: &'a str, what: &str) -> Printed<&'a str> {
    if text == "*" {
        return Ok(text);
    }
    let lexed = lex(text);
    match lexed.tokens.as_slice() {
        [first, last] if matches!(&first.tok, Tok::Ident(v) | Tok::Num(v) if v == text) && last.tok == Tok::Eof => {
            Ok(text)
        }
        _ => unrepresentable(format!("{what} `{text}`"), "it is not an id the language can read back"),
    }
}

fn date(ms: u64) -> Printed<String> {
    time::format(ms).map_or_else(
        || unrepresentable(format!("the instant {ms}"), "the language writes dates up to the year 9999"),
        Ok,
    )
}

/// A float as the lexer reads it: plain digits and a point, never an exponent.
fn float(f: f64) -> Printed<String> {
    if !f.is_finite() {
        return unrepresentable("a number", "a non-finite number has no spelling");
    }
    let text = f.to_string();
    Ok(if text.contains('.') { text } else { format!("{text}.0") })
}

/// An attribute path the parser reads back: `subject.`, `resource.` or `env.` and a name.
fn attr(path: &str) -> Printed<&str> {
    if is_attr_path(path) {
        Ok(path)
    } else {
        unrepresentable(format!("the attribute `{path}`"), "it is not an attribute path the language can read")
    }
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn anchor(a: &Anchor) -> Printed<String> {
    let kind = word(&a.kind, "kind")?;
    Ok(match &a.id {
        Some(id) => format!("{kind}:{}", id_part(id, "id")?),
        None => kind.to_string(),
    })
}

fn anchor_list(items: &[Anchor]) -> Printed<String> {
    let parts: Printed<Vec<String>> = items.iter().map(anchor).collect();
    Ok(format!("[{}]", parts?.join(", ")))
}

fn path(items: &[Anchor], what: &str) -> Printed<String> {
    if items.is_empty() {
        return unrepresentable(what, "a path needs at least one step");
    }
    let parts: Printed<Vec<String>> = items.iter().map(anchor).collect();
    Ok(parts?.join(" > "))
}

fn words(items: &[String], what: &str) -> Printed<String> {
    let parts: Printed<Vec<&str>> = items.iter().map(|i| word(i, what)).collect();
    Ok(format!("[{}]", parts?.join(", ")))
}

fn value(v: &Value) -> Printed<String> {
    Ok(match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => float(*f)?,
        Value::Str(s) => quote(s),
        Value::List(items) => {
            let parts: Printed<Vec<String>> = items.iter().map(value).collect();
            format!("[{}]", parts?.join(", "))
        }
        #[allow(unreachable_patterns, reason = "Value may grow")]
        _ => return unrepresentable("a value", "the syntax does not know this kind of value"),
    })
}

fn operand(o: &Operand) -> Printed<String> {
    match o {
        Operand::Attr { attr: path } => Ok(attr(path)?.to_string()),
        Operand::Lit(v) => value(v),
        #[allow(unreachable_patterns, reason = "Operand may grow")]
        _ => unrepresentable("an operand", "the syntax does not know this kind of operand"),
    }
}

/// `parent` says how tightly the surroundings bind: 0 none, 1 under `or`, 2 under `and`/`not`.
fn condition(c: &Condition, parent: u8) -> Printed<String> {
    let compare =
        |l: &Operand, op: &str, r: &Operand| -> Printed<String> { Ok(format!("{} {op} {}", operand(l)?, operand(r)?)) };
    let group = |of: &[Condition], keyword: &str, func: &str, level: u8| -> Printed<String> {
        if of.len() < 2 {
            let parts: Printed<Vec<String>> = of.iter().map(|c| condition(c, 0)).collect();
            return Ok(format!("{func}({})", parts?.join(", ")));
        }
        let parts: Printed<Vec<String>> = of.iter().map(|c| condition(c, level)).collect();
        let text = parts?.join(&format!(" {keyword} "));
        Ok(if parent >= level { format!("({text})") } else { text })
    };
    match c {
        Condition::Eq { left, right } => compare(left, "==", right),
        Condition::Ne { left, right } => compare(left, "!=", right),
        Condition::Lt { left, right } => compare(left, "<", right),
        Condition::Le { left, right } => compare(left, "<=", right),
        Condition::Gt { left, right } => compare(left, ">", right),
        Condition::Ge { left, right } => compare(left, ">=", right),
        Condition::In { item, set } => compare(item, "in", set),
        Condition::Exists { attr: path } => Ok(format!("exists {}", attr(path)?)),
        Condition::All { of } => group(of, "and", "all", 2),
        Condition::Any { of } => group(of, "or", "any", 1),
        Condition::Not { cond } => Ok(format!("not {}", condition(cond, 3)?)),
        Condition::Call { func, args } => {
            let parts: Printed<Vec<String>> = args.iter().map(operand).collect();
            Ok(format!("@{}({})", word(func, "function")?, parts?.join(", ")))
        }
        #[allow(unreachable_patterns, reason = "Condition may grow")]
        _ => unrepresentable("a condition", "the syntax does not know this kind of condition"),
    }
}

fn rewrite(r: &Rewrite, top: bool) -> Printed<String> {
    let wrap = |text: String| if top { text } else { format!("({text})") };
    let join = |of: &[Rewrite], op: &str| -> Printed<String> {
        let parts: Printed<Vec<String>> = of.iter().map(|r| rewrite(r, false)).collect();
        Ok(parts?.join(op))
    };
    Ok(match r {
        Rewrite::This => "this".to_string(),
        Rewrite::Computed { relation } => word(relation, "relation")?.to_string(),
        Rewrite::TupleToUserset { tupleset, computed } => {
            format!("{}->{}", word(tupleset, "relation")?, word(computed, "relation")?)
        }
        Rewrite::Union { of } if of.len() >= 2 => wrap(join(of, " | ")?),
        Rewrite::Intersection { of } if of.len() >= 2 => wrap(join(of, " & ")?),
        Rewrite::Union { of } => format!("union({})", join(of, ", ")?),
        Rewrite::Intersection { of } => format!("intersection({})", join(of, ", ")?),
        Rewrite::Exclusion { base, subtract } => {
            wrap(format!("{} - {}", rewrite(base, false)?, rewrite(subtract, false)?))
        }
        #[allow(unreachable_patterns, reason = "Rewrite may grow")]
        _ => return unrepresentable("a rewrite", "the syntax does not know this kind of rewrite"),
    })
}

fn matcher(m: &SubjectMatcher) -> Printed<String> {
    Ok(match m {
        SubjectMatcher::Any => "anyone".to_string(),
        SubjectMatcher::Role { id } => format!("role {}", word(id, "role")?),
        SubjectMatcher::User { id } => format!("user {}", id_part(id, "user id")?),
        SubjectMatcher::Principal { name } => format!("principal {}", word(name, "principal")?),
        SubjectMatcher::Relation { relation } => {
            format!("relation {}", word(relation, "relation")?)
        }
        #[allow(unreachable_patterns, reason = "SubjectMatcher may grow")]
        _ => return unrepresentable("a subject matcher", "the syntax does not know it"),
    })
}

fn resource(r: &Resource, what: &str) -> Printed<String> {
    if !r.attrs.is_empty() {
        return unrepresentable(what, "a resource with attributes has no spelling");
    }
    path(&r.path, what)
}

/// A member of an invariant: only its kind and id survive the text.
fn member(s: &Subject) -> Printed<Anchor> {
    let Some(id) = &s.id else {
        return unrepresentable("an invariant member", "a member needs an id");
    };
    if !s.roles.is_empty() || !s.principals.is_empty() || !s.attrs.is_empty() {
        return unrepresentable(
            format!("the member {}:{id}", s.kind),
            "roles, principals and attributes of a member have no spelling",
        );
    }
    Ok(Anchor {
        kind: s.kind.clone(),
        id: Some(id.clone()),
    })
}

fn strategy_name(s: StrategySpec) -> Printed<&'static str> {
    Ok(match s {
        StrategySpec::MostSpecific => "most_specific",
        StrategySpec::DenyOverrides => "deny_overrides",
        StrategySpec::PermitOverrides => "permit_overrides",
        StrategySpec::FirstApplicable => "first_applicable",
        #[allow(unreachable_patterns, reason = "StrategySpec may grow")]
        _ => return unrepresentable("the strategy", "the syntax does not know it"),
    })
}

// ---- layout -------------------------------------------------------------------------------------

impl Printer {
    fn push(&mut self, indent: usize, text: &str) {
        for _ in 0..indent {
            self.out.push_str("  ");
        }
        self.out.push_str(text);
        self.out.push('\n');
    }

    fn blank(&mut self) {
        if !self.out.is_empty() && !self.out.ends_with("\n\n") {
            self.out.push('\n');
        }
    }

    fn comment(text: &str) -> String {
        if text.is_empty() {
            "//".to_string()
        } else {
            format!("// {text}")
        }
    }

    fn has_notes(&self, id: &str) -> bool {
        self.notes.contains_key(id)
    }

    /// Comments above an element; returns the inline one, to put on its first line.
    fn begin(&mut self, indent: usize, id: &str) -> Option<String> {
        let slots = self.notes.get_mut(id)?;
        let before = std::mem::take(&mut slots.before);
        let mut inline = std::mem::take(&mut slots.inline);
        let first = (!inline.is_empty()).then(|| inline.remove(0));
        slots.after.splice(0..0, inline);
        for text in before {
            self.push(indent, &Self::comment(&text));
        }
        first.map(|text| Self::comment(&text))
    }

    /// Comments below an element. When more of the scope follows, a blank line keeps them from
    /// reading back as the comments above the next element.
    fn finish(&mut self, indent: usize, id: &str, last: bool) {
        let after = self
            .notes
            .get_mut(id)
            .map(|slots| std::mem::take(&mut slots.after))
            .unwrap_or_default();
        if after.is_empty() {
            return;
        }
        for text in after {
            self.push(indent, &Self::comment(&text));
        }
        if !last {
            self.blank();
        }
    }

    fn leaf(&mut self, indent: usize, id: &str, text: &str, last: bool) {
        let inline = self.begin(indent, id);
        match inline {
            Some(note) => self.push(indent, &format!("{text}  {note}")),
            None => self.push(indent, text),
        }
        self.finish(indent, id, last);
    }

    fn open(&mut self, indent: usize, id: &str, head: &str) {
        let inline = self.begin(indent, id);
        match inline {
            Some(note) => self.push(indent, &format!("{head} {{  {note}")),
            None => self.push(indent, &format!("{head} {{")),
        }
    }

    fn close(&mut self, indent: usize, id: &str, last: bool) {
        self.push(indent, "}");
        self.finish(indent, id, last);
    }

    /// A comment whose element or field was not written has no place to go: refusing is better
    /// than moving it to another element.
    fn orphans(&mut self) -> Printed<()> {
        let left = std::mem::take(&mut self.notes);
        let stray = left
            .into_iter()
            .find(|(_, slots)| !(slots.before.is_empty() && slots.inline.is_empty() && slots.after.is_empty()));
        match stray {
            Some((key, _)) => unrepresentable(
                format!("the comments of `{key}`"),
                "the element they belong to is not in the policy",
            ),
            None => Ok(()),
        }
    }

    /// The last line of defence: what was written must read back as the same policy with the same
    /// comments, or the printer refuses instead of handing out a text that says something else.
    fn check_round_trip(&self, policy: &Policy) -> Printed<()> {
        match crate::dsl::parse_unvalidated("<printed>", &self.out) {
            Ok(back) if policy.equivalent_unordered(&back.policy) => Ok(()),
            _ => unrepresentable("the policy", "its text does not read back as the same policy"),
        }
    }

    // ---- elements ---------------------------------------------------------------------------

    fn policy(&mut self, p: &Policy) -> Printed<()> {
        self.leaf(0, ids::LANGUAGE, "language blocks", true);
        self.header_group(p)?;
        for def in &p.catalog.permissions {
            self.blank();
            self.permission(def)?;
        }
        for role in &p.roles {
            self.blank();
            self.role(role)?;
        }
        for subject in &p.subjects {
            self.blank();
            self.subject(subject)?;
        }
        for grant in &p.grants {
            self.blank();
            self.grant(grant)?;
        }
        if let Some(relations) = &p.relations {
            if relations.is_empty() {
                return unrepresentable("the relations", "an empty relation list has no spelling");
            }
            for relation in relations {
                self.blank();
                self.relation(relation)?;
            }
        }
        if !p.tuples.is_empty() {
            self.blank();
            self.tuples(p)?;
        }
        for spec in &p.overrides {
            self.blank();
            self.override_spec(spec)?;
        }
        let mut ordinals: BTreeMap<&'static str, usize> = BTreeMap::new();
        for spec in &p.invariants {
            let kind = invariant_kind(spec);
            let ordinal = ordinals.entry(kind).or_insert(0);
            *ordinal += 1;
            self.blank();
            self.invariant(spec, kind, &ids::invariant(kind, *ordinal))?;
        }
        Ok(())
    }

    fn header_group(&mut self, p: &Policy) -> Printed<()> {
        let mut lines: Vec<(&str, String)> = Vec::new();
        if !p.catalog.target_kinds.is_empty() || self.has_notes(ids::TARGET_KINDS) {
            let list = words(&p.catalog.target_kinds, "kind")?;
            lines.push((ids::TARGET_KINDS, format!("target_kinds = {list}")));
        }
        if !p.catalog.broad_targets.is_empty() || self.has_notes(ids::BROAD_TARGETS) {
            let list = words(&p.catalog.broad_targets, "kind")?;
            lines.push((ids::BROAD_TARGETS, format!("broad_targets = {list}")));
        }
        if p.strategy != StrategySpec::default() || self.has_notes(ids::STRATEGY) {
            lines.push((ids::STRATEGY, format!("strategy = {}", strategy_name(p.strategy)?)));
        }
        match p.max_relation_depth {
            Some(depth) => lines.push((ids::MAX_DEPTH, format!("max_depth = {depth}"))),
            None if self.has_notes(ids::MAX_DEPTH) => {
                return unrepresentable("a comment on `max_depth`", "the policy sets no maximum depth");
            }
            None => {}
        }
        if lines.is_empty() {
            return Ok(());
        }
        self.blank();
        let count = lines.len();
        for (at, (id, text)) in lines.into_iter().enumerate() {
            self.leaf(0, id, &text, at + 1 == count);
        }
        Ok(())
    }

    /// The fields of a block, each a `name = value` line.
    fn fields(&mut self, indent: usize, elem: &str, fields: Vec<(&str, String)>, more: bool) {
        let count = fields.len();
        for (at, (name, text)) in fields.into_iter().enumerate() {
            let last = at + 1 == count && !more;
            self.leaf(indent, &ids::field(elem, name), &format!("{name} = {text}"), last);
        }
    }

    fn table(
        &mut self,
        indent: usize,
        elem: &str,
        name: &str,
        entries: &BTreeMap<String, Value>,
        last: bool,
    ) -> Printed<()> {
        let id = ids::field(elem, name);
        self.open(indent, &id, name);
        for (key, item) in entries {
            self.push(indent + 1, &format!("{} = {}", word(key, "key")?, value(item)?));
        }
        self.close(indent, &id, last);
        Ok(())
    }

    fn permission(&mut self, def: &crate::PermissionDef) -> Printed<()> {
        let id = ids::permission(word(&def.key, "permission key")?);
        let mut fields: Vec<(&str, String)> = Vec::new();
        if let Some(label) = &def.label {
            fields.push(("label", quote(label)));
        }
        if let Some(description) = &def.description {
            fields.push(("description", quote(description)));
        }
        fields.push(("targets", words(&def.targets, "kind")?));
        if !def.implied_by.is_empty() {
            fields.push(("implied_by", words(&def.implied_by, "permission")?));
        }
        if !def.depends_on.is_empty() {
            fields.push(("depends_on", words(&def.depends_on, "permission")?));
        }
        for (name, on) in [
            ("non_delegable", def.non_delegable),
            ("management_only", def.management_only),
            ("override_only", def.override_only),
        ] {
            if on {
                fields.push((name, "true".to_string()));
            }
        }
        self.open(0, &id, &format!("permission {}", def.key));
        let has_meta = !def.meta.is_empty();
        self.fields(1, &id, fields, has_meta);
        if has_meta {
            self.table(1, &id, "meta", &def.meta, true)?;
        }
        self.close(0, &id, true);
        Ok(())
    }

    fn role(&mut self, role: &crate::RoleSpec) -> Printed<()> {
        let name = word(&role.role, "role")?;
        let id = ids::role(name);
        self.open(0, &id, &format!("role {name}"));
        if !role.inherits.is_empty() {
            let list = words(&role.inherits, "role")?;
            self.fields(1, &id, vec![("inherits", list)], false);
        }
        self.close(0, &id, true);
        Ok(())
    }

    fn subject(&mut self, s: &Subject) -> Printed<()> {
        let Some(sid) = &s.id else {
            return unrepresentable("a subject", "a subject needs an id");
        };
        let head = format!("{}:{}", word(&s.kind, "kind")?, id_part(sid, "id")?);
        let id = ids::subject(&s.kind, sid);
        self.open(0, &id, &format!("subject {head}"));
        let mut parts = 0;
        let total = usize::from(!s.principals.is_empty()) + usize::from(!s.attrs.is_empty()) + s.roles.len();
        if !s.principals.is_empty() {
            parts += 1;
            let list = words(&s.principals, "principal")?;
            self.leaf(
                1,
                &ids::field(&id, "principals"),
                &format!("principals = {list}"),
                parts == total,
            );
        }
        if !s.attrs.is_empty() {
            parts += 1;
            self.table(1, &id, "attrs", &s.attrs, parts == total)?;
        }
        for assignment in &s.roles {
            parts += 1;
            let role = word(&assignment.role, "role")?;
            let assign_id = ids::assign(&id, role);
            self.open(1, &assign_id, &format!("assign {role}"));
            let mut fields: Vec<(&str, String)> = Vec::new();
            if let Some(scope) = &assignment.scope {
                fields.push(("scope", anchor(scope)?));
            }
            if let Some(from) = assignment.valid_from {
                fields.push(("valid_from", date(from)?));
            }
            if let Some(until) = assignment.valid_until {
                fields.push(("valid_until", date(until)?));
            }
            self.fields(2, &assign_id, fields, false);
            self.close(1, &assign_id, parts == total);
        }
        self.close(0, &id, true);
        Ok(())
    }

    fn grant(&mut self, g: &crate::Grant) -> Printed<()> {
        let name = word(&g.id, "grant id")?;
        let id = ids::grant(name);
        let effect = match g.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            #[allow(unreachable_patterns, reason = "Effect may grow")]
            _ => return unrepresentable("a grant", "the syntax does not know its effect"),
        };
        let mut fields: Vec<(&str, String)> = vec![
            ("effect", effect.to_string()),
            ("subject", matcher(&g.subject)?),
            ("permission", word(&g.permission, "permission")?.to_string()),
            (
                "target",
                anchor(&Anchor {
                    kind: g.target.kind.clone(),
                    id: g.target.id.clone(),
                })?,
            ),
        ];
        if let Some(scope) = &g.scope {
            fields.push(("scope", anchor(scope)?));
        }
        if let Some(when) = &g.condition {
            fields.push(("when", condition(when, 0)?));
        }
        if let Some(from) = g.valid_from {
            fields.push(("valid_from", date(from)?));
        }
        if let Some(until) = g.valid_until {
            fields.push(("valid_until", date(until)?));
        }
        self.open(0, &id, &format!("grant {name}"));
        self.fields(1, &id, fields, false);
        self.close(0, &id, true);
        Ok(())
    }

    fn relation(&mut self, r: &crate::RelationSpec) -> Printed<()> {
        let kind = word(&r.kind, "kind")?;
        let relation = word(&r.relation, "relation")?;
        let id = ids::relation(kind, relation);
        self.open(0, &id, &format!("relation {kind}#{relation}"));
        self.fields(1, &id, vec![("rewrite", rewrite(&r.rewrite, true)?)], false);
        self.close(0, &id, true);
        Ok(())
    }

    fn tuples(&mut self, p: &Policy) -> Printed<()> {
        self.open(0, ids::TUPLES, "tuples");
        let count = p.tuples.len();
        for (at, tuple) in p.tuples.iter().enumerate() {
            word(&tuple.object.kind, "tuple kind")?;
            id_part(&tuple.object.id, "tuple id")?;
            word(&tuple.relation, "tuple relation")?;
            let (subject, set) = match &tuple.subject {
                TupleSubject::Object(object) => (object, None),
                TupleSubject::Userset(object, relation) => (object, Some(relation)),
                #[allow(unreachable_patterns, reason = "TupleSubject may grow")]
                _ => return unrepresentable("a tuple", "the syntax does not know its subject"),
            };
            word(&subject.kind, "tuple subject kind")?;
            id_part(&subject.id, "tuple subject id")?;
            if let Some(relation) = set {
                word(relation, "tuple subject relation")?;
            }
            let text = tuple.to_string();
            self.leaf(1, &ids::tuple(&text), &text, at + 1 == count);
        }
        self.close(0, ids::TUPLES, true);
        Ok(())
    }

    fn override_spec(&mut self, spec: &crate::OverrideSpec) -> Printed<()> {
        let (id, head, argument) = match &spec.rule {
            OverrideRule::ResourceOwner { attr } => (
                ids::override_owner(attr),
                "override resource_owner",
                ("attr", quote(attr)),
            ),
            OverrideRule::PermissionHolder { permission } => (
                ids::override_holder(permission),
                "override permission_holder",
                ("permission", word(permission, "permission")?.to_string()),
            ),
            #[allow(unreachable_patterns, reason = "OverrideRule may grow")]
            _ => return unrepresentable("an override", "the syntax does not know it"),
        };
        let mut fields = vec![argument];
        if !spec.except.is_empty() {
            fields.push(("except", words(&spec.except, "permission")?));
        }
        self.open(0, &id, head);
        self.fields(1, &id, fields, false);
        self.close(0, &id, true);
        Ok(())
    }

    fn invariant(&mut self, spec: &InvariantSpec, kind: &str, id: &str) -> Printed<()> {
        let mut fields: Vec<(&str, String)> = Vec::new();
        match spec {
            InvariantSpec::RequirePermission {
                permission,
                resource: r,
            } => {
                fields.push(("permission", word(permission, "permission")?.to_string()));
                fields.push(("resource", resource(r, "the resource")?));
            }
            InvariantSpec::NoLockout {
                permissions,
                members,
                resource: r,
                reserve,
            } => {
                fields.push(("permissions", words(permissions, "permission")?));
                let members: Printed<Vec<Anchor>> = members.iter().map(member).collect();
                fields.push(("members", anchor_list(&members?)?));
                fields.push(("resource", resource(r, "the resource")?));
                if let Some(reserve) = reserve {
                    let admin = &reserve.admin_role;
                    if admin.valid_from.is_some() || admin.valid_until.is_some() {
                        return unrepresentable("the reserve role", "a window on the reserve has no spelling");
                    }
                    fields.push(("reserve_role", word(&admin.role, "role")?.to_string()));
                    if let Some(scope) = &admin.scope {
                        fields.push(("reserve_scope", anchor(scope)?));
                    }
                    let subjects: Printed<Vec<Anchor>> = reserve.subjects.iter().map(member).collect();
                    fields.push(("reserve_subjects", anchor_list(&subjects?)?));
                }
            }
            InvariantSpec::NonDelegable { manager } => {
                fields.push(("manager", word(manager, "permission")?.to_string()));
            }
            InvariantSpec::ManagementOnly { roles } => fields.push(("roles", words(roles, "role")?)),
            InvariantSpec::NoEscalation { bypass: Some(b) } => {
                fields.push(("bypass", word(&b.permission, "permission")?.to_string()));
                if !b.resource.path.is_empty() {
                    fields.push(("on", resource(&b.resource, "the bypass resource")?));
                }
            }
            InvariantSpec::Forbid { subject, permissions } => {
                fields.push(("subject", matcher(subject)?));
                fields.push(("permissions", words(permissions, "permission")?));
            }
            _ => {}
        }
        self.open(0, id, &format!("invariant {kind}"));
        self.fields(1, id, fields, false);
        self.close(0, id, true);
        Ok(())
    }
}
