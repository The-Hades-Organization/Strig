//! Separation of duties.
//!
//! Static: the catalog declares sets of roles or permissions nobody accumulates
//! ([`MutualExclusion`](crate::MutualExclusion)) and [`SeparationOfDuties`] refuses the change that
//! would create the accumulation, reached by a direct role, an inherited one, a grant or a temporary
//! elevation.
//!
//! Dynamic: the catalog declares rules "who did `first` on a resource does not do `then` on it"
//! ([`ActionConflict`](crate::ActionConflict)). The engine evaluates them in every decision, before
//! the overrides, from a history the caller supplies as a resource attribute (or in `env`); the core
//! does no IO.

use std::borrow::Cow;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::catalog::{ActionConflict, ExclusiveKind, MutualExclusion};
use crate::decision::Request;
use crate::engine::{Context, Engine};
use crate::governance::{Invariant, Mutation, PROBE_ID, Proposal, Violation, matcher_subject, standing_roles};
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::overrides::{Override, OverrideReach, ReachRequest};
use crate::resource::{Anchor, Resource};
use crate::subject::Subject;

/// Prefix of the name a dynamic rule has as an override (`separation:<rule>`), in the reason of the
/// decision and in the explanation.
pub const SEPARATION_PREFIX: &str = "separation:";

/// Two members of a [`MutualExclusion`] that one subject holds in the same scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Clash {
    pub set: String,
    pub of: ExclusiveKind,
    pub first: String,
    pub second: String,
    /// Where they clash: `None` for a global set, otherwise the anchor (`org:1`, or `org` when the
    /// holding is not tied to one instance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl Clash {
    fn key(&self) -> (&str, &str, &str, Option<&str>) {
        (&self.set, &self.first, &self.second, self.scope.as_deref())
    }

    /// `conjunto 'x' (escopo): 'a' e 'b' não podem ser acumulados por who`.
    pub fn describe(&self, who: &str) -> String {
        let scope = self.scope.as_deref().unwrap_or("global");
        format!(
            "conjunto '{}' ({scope}): '{}' e '{}' não podem ser acumulados por {who}",
            self.set, self.first, self.second
        )
    }
}

struct Held {
    member: String,
    confinement: Option<Anchor>,
}

fn confinement(set: &MutualExclusion, candidates: &[Option<&Anchor>]) -> Option<Anchor> {
    let kind = set.anchor.as_deref()?;
    let of_kind: Vec<&Anchor> = candidates
        .iter()
        .flatten()
        .copied()
        .filter(|a| a.kind == kind)
        .collect();
    of_kind
        .iter()
        .find(|a| a.id.is_some())
        .or_else(|| of_kind.first())
        .map(|a| (*a).clone())
}

fn held_roles(engine: &Engine, set: &MutualExclusion, subject: &Subject, now: Option<u64>) -> Vec<Held> {
    let mut held = Vec::new();
    for assignment in standing_roles(subject, now) {
        for role in engine.roles().expand([assignment.role.as_str()]) {
            if set.members.contains(&role) {
                held.push(Held {
                    member: role,
                    confinement: confinement(set, &[assignment.scope.as_ref()]),
                });
            }
        }
    }
    held
}

fn held_permissions(
    engine: &Engine,
    set: &MutualExclusion,
    subject: &Subject,
    grants: &[Grant],
    now: Option<u64>,
) -> Vec<Held> {
    let mut held = Vec::new();
    for grant in grants
        .iter()
        .filter(|g| g.effect == Effect::Allow && !g.validity().has_ended(now))
    {
        let members: Vec<&String> = set
            .members
            .iter()
            .filter(|m| engine.catalog().implies(&grant.permission, m))
            .collect();
        if members.is_empty() {
            continue;
        }
        let role_scopes: Vec<Option<&Anchor>> = match &grant.subject {
            SubjectMatcher::User { id } if subject.id.as_deref() == Some(id.as_str()) => vec![None],
            SubjectMatcher::Role { id } => standing_roles(subject, now)
                .filter(|r| engine.roles().expand([r.role.as_str()]).contains(id))
                .map(|r| r.scope.as_ref())
                .collect(),
            SubjectMatcher::Principal { name } if subject.principals.contains(name) => vec![None],
            SubjectMatcher::Any => vec![None],
            _ => Vec::new(),
        };
        let target = Anchor {
            kind: grant.target.kind.clone(),
            id: grant.target.id.clone(),
        };
        for role_scope in role_scopes {
            for member in &members {
                held.push(Held {
                    member: (*member).clone(),
                    confinement: confinement(set, &[Some(&target), grant.scope.as_ref(), role_scope]),
                });
            }
        }
    }
    held
}

fn overlap(a: &Option<Anchor>, b: &Option<Anchor>) -> Option<Option<Anchor>> {
    match (a, b) {
        (None, None) => Some(None),
        (Some(x), None) | (None, Some(x)) => Some(Some(x.clone())),
        (Some(x), Some(y)) if x.id.is_none() => Some(Some(y.clone())),
        (Some(x), Some(y)) if y.id.is_none() || x.id == y.id => Some(Some(x.clone())),
        _ => None,
    }
}

fn scope_label(set: &MutualExclusion, anchor: &Option<Anchor>) -> Option<String> {
    let kind = set.anchor.as_deref()?;
    Some(match anchor {
        Some(Anchor { id: Some(id), .. }) => format!("{kind}:{id}"),
        _ => kind.to_string(),
    })
}

/// The pairs of members of the catalog's sets that `subject` holds in the same scope, over `grants`,
/// counting what stands at `now` (an assignment that starts later counts). Denies are ignored: a
/// `deny` is never read as taking a member away. A grant by relation depends on tuples and is not
/// read.
pub fn clashes_of(engine: &Engine, subject: &Subject, grants: &[Grant], now: Option<u64>) -> Vec<Clash> {
    let mut found: Vec<Clash> = Vec::new();
    for set in engine.catalog().mutual_exclusions() {
        let held = match set.of {
            ExclusiveKind::Roles => held_roles(engine, set, subject, now),
            ExclusiveKind::Permissions => held_permissions(engine, set, subject, grants, now),
        };
        for (i, a) in held.iter().enumerate() {
            for b in &held[i + 1..] {
                if a.member == b.member {
                    continue;
                }
                let Some(common) = overlap(&a.confinement, &b.confinement) else {
                    continue;
                };
                let (first, second) = if a.member <= b.member {
                    (a.member.clone(), b.member.clone())
                } else {
                    (b.member.clone(), a.member.clone())
                };
                let clash = Clash {
                    set: set.name.clone(),
                    of: set.of,
                    first,
                    second,
                    scope: scope_label(set, &common),
                };
                if !found.iter().any(|c| c.key() == clash.key()) {
                    found.push(clash);
                }
            }
        }
    }
    found
}

/// Nobody accumulates two members of a [`MutualExclusion`] of the catalog in the same scope. The
/// change is refused when it would create a clash that did not exist: assigning a role, adding an
/// `allow` grant (including a temporary elevation) or a role change that carries it by inheritance.
/// Removing and revoking never create one, so a violated set can always be repaired.
///
/// The subject of a role change is judged with the role applied. An added grant is judged for the
/// subject it names, the actor of the change and the `subjects` the invariant knows, plus a probe
/// holding only what the grant's matcher selects (a role that confers both members by itself is a
/// clash). A grant's condition is not evaluated (the clash is counted), and a `deny` never lifts
/// a member: both fail on the side of refusing.
#[derive(Debug, Clone, Default)]
pub struct SeparationOfDuties {
    subjects: Vec<Subject>,
}

impl SeparationOfDuties {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subjects whose current roles and grants an added grant is also judged against, besides the
    /// one it names and the actor.
    #[must_use]
    pub fn with_subjects<I: IntoIterator<Item = Subject>>(mut self, subjects: I) -> Self {
        self.subjects.extend(subjects);
        self
    }

    fn new_clashes(
        &self,
        engine: &Engine,
        proposal: &Proposal<'_>,
        before: &Subject,
        after: &Subject,
    ) -> Option<(Clash, String)> {
        let was = clashes_of(engine, before, proposal.before, proposal.now);
        let who = after.id.clone().unwrap_or_else(|| "o sujeito".to_string());
        clashes_of(engine, after, proposal.after, proposal.now)
            .into_iter()
            .find(|c| !was.iter().any(|w| w.key() == c.key()))
            .map(|c| (c, who))
    }
}

fn matcher_label(matcher: &SubjectMatcher) -> String {
    match matcher {
        SubjectMatcher::User { id } => id.clone(),
        SubjectMatcher::Role { id } => format!("o papel {id}"),
        SubjectMatcher::Principal { name } => format!("o principal {name}"),
        SubjectMatcher::Any => "qualquer sujeito".to_string(),
        SubjectMatcher::Relation { .. } => "quem tem a relação".to_string(),
    }
}

impl Invariant for SeparationOfDuties {
    fn name(&self) -> &str {
        "separation_of_duties"
    }

    fn check(&self, engine: &Engine, proposal: &Proposal<'_>) -> Result<(), Violation> {
        if engine.catalog().mutual_exclusions().is_empty() {
            return Ok(());
        }
        let found = match proposal.mutation {
            Mutation::AssignRole { subject, .. } => {
                let after = proposal.subject_after(subject);
                self.new_clashes(engine, proposal, subject, &after)
            }
            Mutation::Add(grant) if grant.effect == Effect::Allow => {
                let probe = matcher_subject(&grant.subject);
                let mut candidates: Vec<Cow<'_, Subject>> = self.subjects.iter().map(Cow::Borrowed).collect();
                candidates.push(Cow::Borrowed(proposal.actor));
                candidates.extend(probe.map(Cow::Owned));
                let mut found = None;
                for candidate in &candidates {
                    if let Some((clash, who)) = self.new_clashes(engine, proposal, candidate, candidate) {
                        let who = if candidate.id.as_deref() == Some(PROBE_ID) {
                            matcher_label(&grant.subject)
                        } else {
                            who
                        };
                        found = Some((clash, who));
                        break;
                    }
                }
                found
            }
            _ => None,
        };
        match found {
            Some((clash, who)) => Err(Violation::new(self.name(), clash.describe(&who))),
            None => Ok(()),
        }
    }
}

/// An entry of the history of a resource.
struct Entry<'a> {
    action: &'a str,
    actor: &'a str,
    roles: Vec<&'a str>,
}

fn parse_entry(raw: &Value) -> Option<Entry<'_>> {
    let text = raw.as_str()?;
    let (action, rest) = text.split_once(':')?;
    let (actor, roles) = match rest.split_once('|') {
        Some((actor, roles)) => (actor, roles.split(',').filter(|r| !r.is_empty()).collect()),
        None => (rest, Vec::new()),
    };
    (!action.is_empty() && !actor.is_empty()).then_some(Entry { action, actor, roles })
}

/// The history the rule reads: the resource's attribute, or `env` when the resource has none. An
/// absent attribute is an empty history; one that is not a list of well-formed entries is an error.
fn read_history<'a>(attr: &str, resource: &'a Resource, env: &'a Attributes) -> Result<Vec<Entry<'a>>, ()> {
    let Some(value) = resource.attrs.get(attr).or_else(|| env.get(attr)) else {
        return Ok(Vec::new());
    };
    match value {
        Value::List(items) => items.iter().map(|i| parse_entry(i).ok_or(())).collect(),
        Value::Null => Ok(Vec::new()),
        _ => Err(()),
    }
}

/// A dynamic rule of the catalog as an override that only denies. See the module documentation for
/// the shape of the history.
#[derive(Debug, Clone)]
pub struct SeparationRule {
    rule: ActionConflict,
    name: String,
}

impl SeparationRule {
    pub fn new(rule: ActionConflict) -> Self {
        let name = format!("{SEPARATION_PREFIX}{}", rule.name);
        Self { rule, name }
    }

    fn applies_to(&self, permission: &str) -> bool {
        self.rule.then.iter().any(|p| p == permission)
    }

    /// `true` when the subject may not do the `then` action on the resource.
    fn refuses(&self, engine: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> bool {
        let Ok(history) = read_history(&self.rule.history, request.resource, ctx.env) else {
            return true;
        };
        let mine: BTreeSet<String> = if self.rule.distinct_roles {
            engine
                .roles()
                .expand(request.subject.roles_at(request.resource, ctx.now))
        } else {
            BTreeSet::new()
        };
        history
            .iter()
            .filter(|e| self.rule.first.iter().any(|p| p == e.action))
            .any(|author| {
                let Some(id) = request.subject.id.as_deref() else {
                    return true;
                };
                if id == author.actor {
                    return true;
                }
                if !self.rule.distinct_roles {
                    return false;
                }
                author.roles.is_empty() || !engine.roles().expand(author.roles.iter().copied()).is_disjoint(&mine)
            })
    }
}

impl Override for SeparationRule {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, engine: &Engine, ctx: &Context<'_>, request: &Request<'_>) -> Option<Effect> {
        (self.applies_to(request.permission) && self.refuses(engine, ctx, request)).then_some(Effect::Deny)
    }

    fn reach(&self, request: &ReachRequest<'_>) -> OverrideReach {
        if self.applies_to(request.permission) {
            OverrideReach::Opaque
        } else {
            OverrideReach::Never
        }
    }
}
