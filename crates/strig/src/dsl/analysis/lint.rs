//! `lint`: findings about a policy that no decision ever shows.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::attr::Attributes;
use crate::catalog::Catalog;
use crate::condition::{Condition, ConditionRegistry, EvalContext, Operand};
use crate::dsl::error::Location;
use crate::dsl::policy::{Origins, Policy, ids};
use crate::governance::matcher_subject;
use crate::grant::{Effect, Grant, SubjectMatcher};
use crate::resource::{GLOBAL, Resource};
use crate::separation::clashes_of;
use crate::spec::StrategySpec;
use crate::subject::Subject;

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    /// Worth knowing; often intended (grants kept in a database, for one).
    Info,
    /// Dead or misleading policy: something written that cannot take effect.
    Warning,
    /// Reserved for findings that make the policy wrong.
    Error,
}

impl Severity {
    /// The word used in output and in `--fail-on`.
    pub const fn name(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// The kinds of finding. The code (`L001`) never changes meaning and is never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LintCode {
    /// A grant that never decides because another one always wins before it.
    ShadowedGrant,
    /// A `deny` that cannot change any decision: nothing it could take away is ever allowed.
    UnreachableDeny,
    /// A catalog permission no grant allows to anyone.
    UnheldPermission,
    /// A role no grant, subject or inheritance uses.
    UnusedRole,
    /// An `implied_by` entry already implied by another entry, repeated, or the permission itself.
    RedundantImpliedBy,
    /// A condition that is false whatever the subject, the resource and the environment.
    ConditionAlwaysFalse,
    /// A condition that is true whatever the subject, the resource and the environment.
    ConditionAlwaysTrue,
    /// A field a permission declares that no `allow` grant ever reaches.
    FieldNeverGranted,
    /// A subject, or whoever a grant's matcher selects, already holds two members of a
    /// `mutually_exclusive` set in the same scope.
    SeparationViolated,
}

impl LintCode {
    /// Every code, in order.
    pub const ALL: [LintCode; 9] = [
        LintCode::ShadowedGrant,
        LintCode::UnreachableDeny,
        LintCode::UnheldPermission,
        LintCode::UnusedRole,
        LintCode::RedundantImpliedBy,
        LintCode::ConditionAlwaysFalse,
        LintCode::ConditionAlwaysTrue,
        LintCode::FieldNeverGranted,
        LintCode::SeparationViolated,
    ];

    /// The stable code: `L001`, `L002`, ...
    pub const fn code(self) -> &'static str {
        match self {
            LintCode::ShadowedGrant => "L001",
            LintCode::UnreachableDeny => "L002",
            LintCode::UnheldPermission => "L003",
            LintCode::UnusedRole => "L004",
            LintCode::RedundantImpliedBy => "L005",
            LintCode::ConditionAlwaysFalse => "L006",
            LintCode::ConditionAlwaysTrue => "L007",
            LintCode::FieldNeverGranted => "L008",
            LintCode::SeparationViolated => "L009",
        }
    }

    /// The kebab-case name, accepted wherever the code is.
    pub const fn name(self) -> &'static str {
        match self {
            LintCode::ShadowedGrant => "shadowed-grant",
            LintCode::UnreachableDeny => "unreachable-deny",
            LintCode::UnheldPermission => "unheld-permission",
            LintCode::UnusedRole => "unused-role",
            LintCode::RedundantImpliedBy => "redundant-implied-by",
            LintCode::ConditionAlwaysFalse => "condition-always-false",
            LintCode::ConditionAlwaysTrue => "condition-always-true",
            LintCode::FieldNeverGranted => "field-never-granted",
            LintCode::SeparationViolated => "separation-violated",
        }
    }

    /// How much the finding matters.
    pub const fn severity(self) -> Severity {
        match self {
            LintCode::ShadowedGrant
            | LintCode::UnreachableDeny
            | LintCode::ConditionAlwaysFalse
            | LintCode::FieldNeverGranted
            | LintCode::SeparationViolated => Severity::Warning,
            LintCode::UnheldPermission
            | LintCode::UnusedRole
            | LintCode::RedundantImpliedBy
            | LintCode::ConditionAlwaysTrue => Severity::Info,
        }
    }

    /// Reads a code (`L001`, case-insensitive) or a name (`shadowed-grant`).
    pub fn parse(text: &str) -> Option<LintCode> {
        let text = text.trim();
        Self::ALL
            .into_iter()
            .find(|c| c.code().eq_ignore_ascii_case(text) || c.name() == text)
    }
}

/// One thing the lint found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Finding {
    /// The stable code (`L001`).
    pub code: String,
    /// The name of the code (`shadowed-grant`).
    pub name: String,
    /// How much it matters.
    pub severity: Severity,
    /// What is wrong, naming the elements.
    pub message: String,
    /// What to do about it.
    pub hint: String,
    /// The element the finding is about, by its id in the policy (`grant:g`, `role:r`, `permission:p`).
    pub element: String,
    /// Where the element is written, when the policy came from sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// The line of the element, from 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The column of the element, from 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl Finding {
    /// The code as a [`LintCode`].
    pub fn lint_code(&self) -> Option<LintCode> {
        LintCode::parse(&self.code)
    }

    /// `file:line:column`, when the finding has a position.
    pub fn position(&self) -> Option<String> {
        match (&self.file, self.line, self.column) {
            (Some(file), Some(line), Some(column)) => Some(format!("{file}:{line}:{column}")),
            _ => None,
        }
    }
}

/// What to leave out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LintOptions {
    /// Codes (`L004`) or names (`unused-role`) to drop from the result.
    pub ignore: Vec<String>,
}

impl LintOptions {
    /// Drops the findings with this code or name.
    #[must_use]
    pub fn ignoring(mut self, code: impl Into<String>) -> Self {
        self.ignore.push(code.into());
        self
    }
}

/// Lints a policy. `origins` gives each finding its position; without it the findings carry the
/// element only. The result is sorted by position, then code, and never holds an ignored code.
pub fn lint(policy: &Policy, origins: Option<&Origins>, options: &LintOptions) -> Vec<Finding> {
    let ignored: BTreeSet<LintCode> = options.ignore.iter().filter_map(|c| LintCode::parse(c)).collect();
    let catalog = Catalog::from_export(policy.catalog.clone()).ok();
    let cx = Cx {
        policy,
        origins,
        catalog: catalog.as_ref(),
        found: std::cell::RefCell::new(Vec::new()),
    };
    let wanted = |code: LintCode| !ignored.contains(&code);
    if wanted(LintCode::ShadowedGrant) {
        cx.shadowed_grants();
    }
    if wanted(LintCode::UnreachableDeny) {
        cx.unreachable_denies();
    }
    if wanted(LintCode::UnheldPermission) {
        cx.unheld_permissions();
    }
    if wanted(LintCode::UnusedRole) {
        cx.unused_roles();
    }
    if wanted(LintCode::RedundantImpliedBy) {
        cx.redundant_implied_by();
    }
    if wanted(LintCode::ConditionAlwaysFalse) || wanted(LintCode::ConditionAlwaysTrue) {
        cx.constant_conditions();
    }
    if wanted(LintCode::FieldNeverGranted) {
        cx.fields_never_granted();
    }
    if wanted(LintCode::SeparationViolated) {
        cx.separation_violated();
    }
    let mut found = cx.found.into_inner();
    found.retain(|f| f.lint_code().is_none_or(wanted));
    found.sort_by(|a, b| {
        (&a.file, a.line, a.column, &a.code, &a.element).cmp(&(&b.file, b.line, b.column, &b.code, &b.element))
    });
    found
}

struct Cx<'a> {
    policy: &'a Policy,
    origins: Option<&'a Origins>,
    catalog: Option<&'a Catalog>,
    found: std::cell::RefCell<Vec<Finding>>,
}

impl Cx<'_> {
    fn report(&self, code: LintCode, element: String, at: &str, message: String, hint: &str) {
        let place: Option<&Location> = self.origins.and_then(|o| o.get(at));
        self.found.borrow_mut().push(Finding {
            code: code.code().to_string(),
            name: code.name().to_string(),
            severity: code.severity(),
            message,
            hint: hint.to_string(),
            element,
            file: place.map(|l| l.file.to_string()),
            line: place.map(|l| l.line),
            column: place.map(|l| l.column),
        });
    }

    fn grants(&self) -> &[Grant] {
        &self.policy.grants
    }

    fn effective<'b>(&'b self, permission: &'b str) -> BTreeSet<&'b str> {
        match self.catalog.and_then(|c| c.effective(permission)) {
            Some(set) => set.iter().map(String::as_str).collect(),
            None => BTreeSet::from([permission]),
        }
    }

    fn descendants_and_self(&self, permission: &str) -> BTreeSet<String> {
        let mut all = self.catalog.map(|c| c.descendants(permission)).unwrap_or_default();
        all.insert(permission.to_string());
        all
    }

    fn has_overrides(&self) -> bool {
        !self.policy.overrides.is_empty()
    }

    fn allowed_by_grants(&self, permission: &str) -> impl Iterator<Item = &Grant> {
        let reach: BTreeSet<String> = self.effective(permission).into_iter().map(str::to_string).collect();
        self.grants()
            .iter()
            .filter(move |g| g.effect == Effect::Allow && reach.contains(&g.permission))
    }

    fn shadowed_grants(&self) {
        let strategy = self.policy.strategy;
        for (at, grant) in self.grants().iter().enumerate() {
            let shadow = self
                .grants()
                .iter()
                .enumerate()
                .find(|(other_at, other)| *other_at != at && self.shadows(strategy, *other_at < at, other, grant));
            let Some((_, by)) = shadow else { continue };
            self.report(
                LintCode::ShadowedGrant,
                ids::grant(&grant.id),
                &ids::grant(&grant.id),
                format!(
                    "grant `{}` ({} {}) never decides: grant `{}` ({}) applies whenever it does and always wins",
                    grant.id,
                    effect_word(grant.effect),
                    grant.permission,
                    by.id,
                    effect_word(by.effect),
                ),
                "remove the grant, or narrow the one that shadows it",
            );
        }
    }

    fn shadows(&self, strategy: StrategySpec, earlier: bool, h: &Grant, g: &Grant) -> bool {
        if !self.covers(h, g) {
            return false;
        }
        match strategy {
            StrategySpec::MostSpecific => {
                h.effect == Effect::Deny && g.effect == Effect::Allow && h.target.kind == g.target.kind
            }
            StrategySpec::DenyOverrides => h.effect == Effect::Deny && g.effect == Effect::Allow,
            StrategySpec::PermitOverrides => h.effect == Effect::Allow && g.effect == Effect::Deny,
            StrategySpec::FirstApplicable => earlier,
        }
    }

    /// Does `h` apply on every request on which `g` applies?
    fn covers(&self, h: &Grant, g: &Grant) -> bool {
        h.permission == g.permission
            && self.subject_covers(&h.subject, &g.subject)
            && target_covers(h, g)
            && h.scope.as_ref().is_none_or(|s| g.scope.as_ref() == Some(s))
            && window_covers(h, g)
            && condition_implies(g.condition.as_ref(), h.condition.as_ref())
            && (h.fields.is_empty() || (!g.fields.is_empty() && g.fields.iter().all(|f| h.fields.contains(f))))
    }

    fn subject_covers(&self, h: &SubjectMatcher, g: &SubjectMatcher) -> bool {
        match (h, g) {
            (SubjectMatcher::Any, _) => true,
            (SubjectMatcher::Role { id: outer }, SubjectMatcher::Role { id: inner }) => {
                outer == inner || self.role_inherits(inner, outer)
            }
            _ => h == g,
        }
    }

    fn role_inherits(&self, role: &str, ancestor: &str) -> bool {
        let parents: BTreeMap<&str, &[String]> = self
            .policy
            .roles
            .iter()
            .map(|r| (r.role.as_str(), r.inherits.as_slice()))
            .collect();
        let mut seen = BTreeSet::new();
        let mut stack = vec![role];
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                continue;
            }
            for parent in parents.get(current).copied().unwrap_or_default() {
                if parent == ancestor {
                    return true;
                }
                stack.push(parent);
            }
        }
        false
    }

    fn unreachable_denies(&self) {
        if self.has_overrides() {
            return;
        }
        let Some(catalog) = self.catalog else { return };
        for grant in self.grants().iter().filter(|g| g.effect == Effect::Deny) {
            if !catalog.contains(&grant.permission) {
                continue;
            }
            let affected = self.descendants_and_self(&grant.permission);
            let reach: BTreeSet<&str> = affected.iter().flat_map(|p| self.effective(p)).collect();
            let anything_to_take_away = self
                .grants()
                .iter()
                .any(|g| g.effect == Effect::Allow && reach.contains(g.permission.as_str()));
            if anything_to_take_away {
                continue;
            }
            self.report(
                LintCode::UnreachableDeny,
                ids::grant(&grant.id),
                &ids::grant(&grant.id),
                format!(
                    "deny `{}` on {} cannot change any decision: no grant allows {} or what it implies",
                    grant.id, grant.permission, grant.permission
                ),
                "remove the deny, or add the allow it is meant to restrict",
            );
        }
    }

    fn unheld_permissions(&self) {
        let Some(catalog) = self.catalog else { return };
        for def in catalog.all() {
            if def.override_only || self.allowed_by_grants(&def.key).next().is_some() {
                continue;
            }
            if self.has_overrides() && !self.policy.overrides.iter().all(|o| o.except.contains(&def.key)) {
                continue;
            }
            self.report(
                LintCode::UnheldPermission,
                ids::permission(&def.key),
                &ids::permission(&def.key),
                format!(
                    "permission `{}` is in the catalog and no grant allows it to anyone",
                    def.key
                ),
                "add the grant, or drop the permission; ignore the code when grants live outside the sources",
            );
        }
    }

    fn unused_roles(&self) {
        let referenced: BTreeSet<&str> = self
            .grants()
            .iter()
            .filter_map(|g| match &g.subject {
                SubjectMatcher::Role { id } => Some(id.as_str()),
                _ => None,
            })
            .chain(
                self.policy
                    .subjects
                    .iter()
                    .flat_map(|s| s.roles.iter().map(|r| r.role.as_str())),
            )
            .collect();
        let mut linked: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for spec in &self.policy.roles {
            linked.entry(spec.role.as_str()).or_default();
            for parent in &spec.inherits {
                linked.entry(spec.role.as_str()).or_default().insert(parent.as_str());
                linked.entry(parent.as_str()).or_default().insert(spec.role.as_str());
            }
        }
        let mut used: BTreeSet<&str> = BTreeSet::new();
        let mut stack: Vec<&str> = referenced.iter().copied().collect();
        while let Some(role) = stack.pop() {
            if used.insert(role) {
                stack.extend(linked.get(role).into_iter().flatten().copied());
            }
        }
        for spec in &self.policy.roles {
            if used.contains(spec.role.as_str()) {
                continue;
            }
            self.report(
                LintCode::UnusedRole,
                ids::role(&spec.role),
                &ids::role(&spec.role),
                format!(
                    "role `{}` is declared and no grant, subject or related role uses it",
                    spec.role
                ),
                "remove the role, or grant something to it",
            );
        }
    }

    fn redundant_implied_by(&self) {
        let Some(catalog) = self.catalog else { return };
        for def in catalog.all() {
            let at = ids::field(&ids::permission(&def.key), "implied_by");
            let mut seen = BTreeSet::new();
            for (index, parent) in def.implied_by.iter().enumerate() {
                let why = if *parent == def.key {
                    Some("it is the permission itself".to_string())
                } else if !seen.insert(parent.as_str()) {
                    Some("it is listed twice".to_string())
                } else {
                    def.implied_by
                        .iter()
                        .enumerate()
                        .find(|(other, via)| *other != index && via.as_str() != parent && catalog.implies(parent, via))
                        .map(|(_, via)| format!("`{via}`, also listed, is already implied by `{parent}`"))
                };
                let Some(why) = why else { continue };
                self.report(
                    LintCode::RedundantImpliedBy,
                    ids::permission(&def.key),
                    &at,
                    format!("`{parent}` in `implied_by` of `{}` is redundant: {why}", def.key),
                    "remove the entry",
                );
            }
        }
    }

    fn constant_conditions(&self) {
        let registry = ConditionRegistry::default();
        for grant in self.grants() {
            let Some(condition) = &grant.condition else { continue };
            let at = ids::field(&ids::grant(&grant.id), "when");
            match constant(condition, &registry) {
                Some(false) => self.report(
                    LintCode::ConditionAlwaysFalse,
                    ids::grant(&grant.id),
                    &at,
                    format!(
                        "the condition of grant `{}` is always false: the grant never applies",
                        grant.id
                    ),
                    "fix the condition or remove the grant",
                ),
                Some(true) => self.report(
                    LintCode::ConditionAlwaysTrue,
                    ids::grant(&grant.id),
                    &at,
                    format!(
                        "the condition of grant `{}` is always true: it restricts nothing",
                        grant.id
                    ),
                    "remove the condition",
                ),
                None => {}
            }
        }
    }

    fn fields_never_granted(&self) {
        let Some(catalog) = self.catalog else { return };
        for def in catalog.all() {
            if def.fields.is_empty() {
                continue;
            }
            let allows: Vec<&Grant> = self.allowed_by_grants(&def.key).collect();
            if allows.is_empty() {
                continue;
            }
            for field in &def.fields {
                if allows.iter().any(|g| g.covers_field(field)) {
                    continue;
                }
                self.report(
                    LintCode::FieldNeverGranted,
                    ids::permission(&def.key),
                    &ids::permission(&def.key),
                    format!(
                        "field `{field}` of `{}` is declared and no allow grant reaches it",
                        def.key
                    ),
                    "name the field in a grant, or remove it from the permission",
                );
            }
        }
    }

    fn separation_violated(&self) {
        if self.policy.catalog.mutually_exclusive.is_empty() {
            return;
        }
        let Some(engine) = self
            .policy
            .engine_spec()
            .builder()
            .ok()
            .and_then(|builder| builder.build().ok())
        else {
            return;
        };
        let mut seen: BTreeSet<(String, String, String, String)> = BTreeSet::new();
        let mut candidates: Vec<(String, String, Subject)> = Vec::new();
        for subject in &self.policy.subjects {
            let Some(id) = &subject.id else { continue };
            candidates.push((
                ids::subject(&subject.kind, id),
                format!("{}:{id}", subject.kind),
                subject.clone(),
            ));
        }
        for grant in self.grants() {
            let Some(probe) = matcher_subject(&grant.subject) else {
                continue;
            };
            let label = match &grant.subject {
                SubjectMatcher::User { .. } => continue,
                SubjectMatcher::Role { id } => format!("role:{id}"),
                SubjectMatcher::Principal { name } => format!("principal:{name}"),
                _ => "anyone".to_string(),
            };
            candidates.push((ids::grant(&grant.id), label, probe));
        }
        for (element, label, subject) in candidates {
            for clash in clashes_of(&engine, &subject, self.grants(), None) {
                let key = (
                    label.clone(),
                    clash.set.clone(),
                    clash.first.clone(),
                    clash.second.clone(),
                );
                if !seen.insert(key) {
                    continue;
                }
                self.report(
                    LintCode::SeparationViolated,
                    element.clone(),
                    &element,
                    format!(
                        "{label} holds `{}` and `{}` of the {} set `{}`{}",
                        clash.first,
                        clash.second,
                        clash.of.as_str(),
                        clash.set,
                        clash.scope.as_deref().map(|s| format!(" in {s}")).unwrap_or_default()
                    ),
                    "take one of the two away, or remove the set if the duties may be held together",
                );
            }
        }
    }
}

fn effect_word(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    }
}

fn target_covers(h: &Grant, g: &Grant) -> bool {
    if h.target.kind == GLOBAL && h.target.id.is_none() {
        return true;
    }
    h.target.kind == g.target.kind && (h.target.id.is_none() || h.target.id == g.target.id)
}

fn window_covers(h: &Grant, g: &Grant) -> bool {
    let has_window = h.valid_from.is_some() || h.valid_until.is_some();
    if has_window && h.effect == Effect::Allow && g.effect == Effect::Deny {
        return false;
    }
    let from = h.valid_from.is_none_or(|hf| g.valid_from.is_some_and(|gf| hf <= gf));
    let until = h.valid_until.is_none_or(|hu| g.valid_until.is_some_and(|gu| gu <= hu));
    from && until
}

/// Does `given` hold only where `wanted` holds too? Conservative: `false` when unsure.
fn condition_implies(given: Option<&Condition>, wanted: Option<&Condition>) -> bool {
    let Some(wanted) = wanted else { return true };
    let Some(given) = given else { return false };
    if given == wanted {
        return true;
    }
    match (given, wanted) {
        (Condition::All { of }, _) if of.iter().any(|c| condition_implies(Some(c), Some(wanted))) => true,
        (_, Condition::Any { of }) => of.iter().any(|c| condition_implies(Some(given), Some(c))),
        _ => false,
    }
}

/// The value a condition has whatever it reads, when that can be told without evaluating data.
fn constant(condition: &Condition, registry: &ConditionRegistry) -> Option<bool> {
    match condition {
        Condition::Not { cond } => constant(cond, registry).map(|v| !v),
        Condition::All { of } => {
            let values: Vec<Option<bool>> = of.iter().map(|c| constant(c, registry)).collect();
            if values.contains(&Some(false)) || has_complement(of) {
                Some(false)
            } else {
                values.iter().all(|v| *v == Some(true)).then_some(true)
            }
        }
        Condition::Any { of } => {
            let values: Vec<Option<bool>> = of.iter().map(|c| constant(c, registry)).collect();
            if values.contains(&Some(true)) || has_complement(of) {
                Some(true)
            } else {
                values.iter().all(|v| *v == Some(false)).then_some(false)
            }
        }
        Condition::TimeBetween { from, until, .. } if from == until => Some(false),
        Condition::WeekdayIn { days, .. } if days.is_empty() => Some(false),
        Condition::WeekdayIn { days, .. } => {
            let distinct: BTreeSet<&str> = days.iter().map(String::as_str).collect();
            ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
                .iter()
                .all(|d| distinct.contains(d))
                .then_some(true)
        }
        leaf => ground_value(leaf, registry),
    }
}

fn has_complement(of: &[Condition]) -> bool {
    of.iter()
        .any(|a| of.iter().any(|b| matches!(b, Condition::Not { cond } if **cond == *a)))
}

fn ground_value(leaf: &Condition, registry: &ConditionRegistry) -> Option<bool> {
    let operands: Vec<&Operand> = match leaf {
        Condition::Eq { left, right }
        | Condition::Ne { left, right }
        | Condition::Lt { left, right }
        | Condition::Le { left, right }
        | Condition::Gt { left, right }
        | Condition::Ge { left, right }
        | Condition::StartsWith { left, right }
        | Condition::EndsWith { left, right }
        | Condition::Contains { left, right }
        | Condition::AnyIn { left, right }
        | Condition::AllIn { left, right } => vec![left, right],
        Condition::In { item, set } | Condition::IpIn { item, set } => vec![item, set],
        _ => return None,
    };
    if operands.iter().any(|o| !matches!(o, Operand::Lit(_))) {
        return None;
    }
    let subject = Subject::anonymous();
    let resource = Resource::global();
    let env = Attributes::new();
    let ctx = EvalContext {
        subject: &subject,
        resource: &resource,
        env: &env,
    };
    leaf.evaluate(&ctx, registry).ok()
}
