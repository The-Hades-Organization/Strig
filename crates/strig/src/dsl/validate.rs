//! The validator: checks a whole policy, whatever syntax it came from, and says where each
//! problem is. It works on the real types, so a policy loaded from JSON is validated the same way
//! (without positions).

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::dsl::error::{Diagnostic, Location, MAX_DIAGNOSTICS, capped};
use crate::dsl::grammar::closest;
use crate::dsl::policy::{Origins, Policy, ids};
use crate::{
    Catalog, CatalogError, Condition, InvariantSpec, Operand, OverrideRule, Rewrite, RoleAssignment, SubjectMatcher,
    Value,
};

/// More than this many problems are only counted: the report sorts and cuts them afterwards.
const KEPT: usize = MAX_DIAGNOSTICS * 10;

struct Report<'a> {
    origins: Option<&'a Origins>,
    out: Vec<Diagnostic>,
    hidden: usize,
}

impl Report<'_> {
    fn at(&self, id: &str) -> Option<Location> {
        self.origins.and_then(|o| o.get(id)).cloned()
    }

    fn error(&mut self, id: &str, message: impl Into<String>, hint: Option<String>) {
        if self.out.len() >= KEPT {
            self.hidden += 1;
            return;
        }
        let mut diagnostic = Diagnostic::new(self.at(id), message);
        diagnostic.hint = hint;
        self.out.push(diagnostic);
    }
}

/// Every problem of the policy, ordered by position. Empty when the policy is sound.
pub(crate) fn validate(policy: &Policy, origins: Option<&Origins>) -> Vec<Diagnostic> {
    let mut report = Report {
        origins,
        out: Vec::new(),
        hidden: 0,
    };
    let catalog = catalog(policy, &mut report);
    roles(policy, &mut report);
    relations(policy, &mut report);
    grants(policy, catalog.as_ref(), &mut report);
    assignments(policy, &mut report);
    overrides(policy, catalog.as_ref(), &mut report);
    invariants(policy, catalog.as_ref(), &mut report);
    let hidden = report.hidden;
    let mut out = report.out;
    out.sort_by_key(|d| d.location.as_ref().map(|at| (at.file.clone(), at.line, at.column)));
    capped(out, hidden)
}

fn catalog(policy: &Policy, report: &mut Report<'_>) -> Option<Catalog> {
    match Catalog::from_export(policy.catalog.clone()) {
        Ok(catalog) => Some(catalog),
        Err(errors) => {
            for error in errors.0 {
                catalog_error(error, policy, report);
            }
            None
        }
    }
}

/// "did you mean `x`?" when `name` is a slip away from one of `names`, followed by `rest`.
/// Nothing is listed when no name is close, since the set can be large.
fn near<'a>(name: &str, names: impl IntoIterator<Item = &'a str>, rest: Option<String>) -> Option<String> {
    let names: BTreeSet<&str> = names.into_iter().collect();
    let names: Vec<&str> = names.into_iter().collect();
    match (closest(name, &names), rest) {
        (Some(c), Some(rest)) => Some(format!("did you mean `{c}`? or {rest}")),
        (Some(c), None) => Some(format!("did you mean `{c}`?")),
        (None, rest) => rest,
    }
}

fn permission_keys(policy: &Policy) -> impl Iterator<Item = &str> {
    policy.catalog.permissions.iter().map(|p| p.key.as_str())
}

fn catalog_error(error: CatalogError, policy: &Policy, report: &mut Report<'_>) {
    let hint = |text: &str| Some(text.to_string());
    match error {
        CatalogError::InvalidKey(key) => report.error(
            &ids::permission(&key),
            format!("`{key}` is not a valid permission key"),
            hint("use segments of a-z, 0-9 and _ separated by dots"),
        ),
        CatalogError::DuplicateKey(key) => {
            let id = ids::permission(&key);
            report.error(&id, format!("permission `{key}` is declared twice"), None);
        }
        CatalogError::UnknownParent { key, parent } => report.error(
            &format!("{}/implied_by/{parent}", ids::permission(&key)),
            format!("`{key}` is implied by `{parent}`, which is not in the catalog"),
            near(&parent, permission_keys(policy), hint("declare it or fix the name")),
        ),
        CatalogError::UnknownPrerequisite { key, prerequisite } => report.error(
            &format!("{}/depends_on/{prerequisite}", ids::permission(&key)),
            format!("`{key}` depends on `{prerequisite}`, which is not in the catalog"),
            near(&prerequisite, permission_keys(policy), hint("declare it or fix the name")),
        ),
        CatalogError::UnreachablePrerequisite {
            key,
            prerequisite,
            target,
        } => report.error(
            &format!("{}/depends_on/{prerequisite}", ids::permission(&key)),
            format!(
                "`{key}` targets `{target}`, which its prerequisite `{prerequisite}` does not accept, so it could never be allowed"
            ),
            hint("add the target kind to the prerequisite or make it a broad target"),
        ),
        CatalogError::PrerequisiteCycle(path) => {
            let first = path.first().cloned().unwrap_or_default();
            report.error(
                &ids::permission(&first),
                format!("prerequisites form a cycle: {}", path.join(" -> ")),
                None,
            );
        }
        CatalogError::UnknownTarget { key, target } => report.error(
            &format!("{}/targets/{target}", ids::permission(&key)),
            format!("`{key}` targets `{target}`, which is not in target_kinds or broad_targets"),
            near(
                &target,
                policy
                    .catalog
                    .target_kinds
                    .iter()
                    .chain(&policy.catalog.broad_targets)
                    .map(String::as_str),
                hint("add it to target_kinds"),
            ),
        ),
        CatalogError::NoTargets(key) => report.error(
            &ids::permission(&key),
            format!("permission `{key}` has no targets"),
            hint("add a line: targets = [kind]"),
        ),
        CatalogError::Cycle(path) => {
            let first = path.first().cloned().unwrap_or_default();
            report.error(
                &ids::permission(&first),
                format!("implications form a cycle: {}", path.join(" -> ")),
                None,
            );
        }
        CatalogError::Rule { rule, key, message } => report.error(
            &ids::permission(&key),
            format!("`{key}` breaks the catalog rule {rule}: {message}"),
            None,
        ),
    }
}

fn roles(policy: &Policy, report: &mut Report<'_>) {
    let mut seen: HashSet<&str> = HashSet::new();
    let declared: HashSet<&str> = policy.roles.iter().map(|r| r.role.as_str()).collect();
    for role in &policy.roles {
        let id = ids::role(&role.role);
        if !seen.insert(&role.role) {
            report.error(&id, format!("role `{}` is declared twice", role.role), None);
        }
        for parent in &role.inherits {
            if !declared.contains(parent.as_str()) {
                report.error(
                    &format!("{id}/inherits/{parent}"),
                    format!("role `{}` inherits `{parent}`, which is not declared", role.role),
                    near(
                        parent,
                        policy.roles.iter().map(|r| r.role.as_str()),
                        Some(format!("declare it with: role {parent} {{ }}")),
                    ),
                );
            }
        }
    }
    let parents: HashMap<&str, Vec<&str>> = policy
        .roles
        .iter()
        .map(|r| (r.role.as_str(), r.inherits.iter().map(String::as_str).collect()))
        .collect();
    let order: Vec<&str> = policy.roles.iter().map(|r| r.role.as_str()).collect();
    for path in find_cycles(&order, &parents) {
        let head = path.first().copied().unwrap_or_default();
        report.error(
            &ids::role(head),
            format!("roles inherit in a cycle: {}", path.join(" -> ")),
            None,
        );
    }
}

/// Every cycle that a depth-first walk finds, one path per back edge, each starting and ending at
/// the same role. Iterative with colors shared across the roots, so it is O(V + E) and a long
/// chain of roles cannot exhaust the stack.
fn find_cycles<'a>(order: &[&'a str], edges: &HashMap<&'a str, Vec<&'a str>>) -> Vec<Vec<&'a str>> {
    /// `Gray(depth)`: on the current path at that depth. `Black`: finished.
    #[derive(Clone, Copy)]
    enum Color {
        Gray(usize),
        Black,
    }
    /// A cycle is reported once per head and the report stops here, so a hostile graph cannot
    /// make the diagnostics grow with the input.
    const MAX_CYCLES: usize = 100;
    /// Names shown at most per cycle: the rest is elided.
    const SHOWN: usize = 12;
    let mut color: HashMap<&str, Color> = HashMap::new();
    let mut cycles = Vec::new();
    let mut reported: HashSet<&str> = HashSet::new();
    for &root in order {
        if color.contains_key(root) {
            continue;
        }
        color.insert(root, Color::Gray(0));
        let mut path: Vec<&str> = vec![root];
        let mut next: Vec<usize> = vec![0];
        while let (Some(&node), Some(index)) = (path.last(), next.last_mut()) {
            let children = edges.get(node).map_or(&[][..], Vec::as_slice);
            let Some(&child) = children.get(*index) else {
                color.insert(node, Color::Black);
                path.pop();
                next.pop();
                continue;
            };
            *index += 1;
            match color.get(child) {
                None => {
                    color.insert(child, Color::Gray(path.len()));
                    path.push(child);
                    next.push(0);
                }
                Some(Color::Gray(from)) => {
                    if cycles.len() >= MAX_CYCLES {
                        return cycles;
                    }
                    if !reported.insert(child) {
                        continue;
                    }
                    let loop_path = &path[*from..];
                    let mut cycle: Vec<&str> = if loop_path.len() > SHOWN {
                        let mut head = loop_path[..SHOWN / 2].to_vec();
                        head.push("...");
                        head.extend_from_slice(&loop_path[loop_path.len() - SHOWN / 2..]);
                        head
                    } else {
                        loop_path.to_vec()
                    };
                    cycle.push(child);
                    cycles.push(cycle);
                }
                Some(Color::Black) => {}
            }
        }
    }
    cycles
}

fn relations(policy: &Policy, report: &mut Report<'_>) {
    let Some(relations) = &policy.relations else {
        return;
    };
    let mut seen = HashSet::new();
    for relation in relations {
        let id = ids::relation(&relation.kind, &relation.relation);
        if !seen.insert((&relation.kind, &relation.relation)) {
            report.error(
                &id,
                format!("relation `{}#{}` is declared twice", relation.kind, relation.relation),
                None,
            );
        }
        check_rewrite(&relation.rewrite, &id, report);
    }
}

fn check_rewrite(rewrite: &Rewrite, id: &str, report: &mut Report<'_>) {
    match rewrite {
        Rewrite::Union { of } | Rewrite::Intersection { of } => {
            if of.is_empty() {
                report.error(id, "a union or intersection needs at least one operand", None);
            }
            for inner in of {
                check_rewrite(inner, id, report);
            }
        }
        Rewrite::Exclusion { base, subtract } => {
            check_rewrite(base, id, report);
            check_rewrite(subtract, id, report);
        }
        Rewrite::This | Rewrite::Computed { .. } | Rewrite::TupleToUserset { .. } => {}
    }
}

fn window_inverted(from: Option<u64>, until: Option<u64>) -> bool {
    matches!((from, until), (Some(from), Some(until)) if from >= until)
}

fn grants(policy: &Policy, catalog: Option<&Catalog>, report: &mut Report<'_>) {
    let mut seen: HashSet<&str> = HashSet::new();
    for grant in &policy.grants {
        let id = ids::grant(&grant.id);
        if !seen.insert(&grant.id) {
            report.error(&id, format!("grant `{}` is declared twice", grant.id), None);
        }
        if window_inverted(grant.valid_from, grant.valid_until) {
            report.error(
                &ids::field(&id, "valid_until"),
                "valid_until is not after valid_from",
                Some("the window starts at valid_from and ends, exclusive, at valid_until".into()),
            );
        }
        if let Some(condition) = &grant.condition {
            condition_names(condition, &ids::field(&id, "when"), report);
        }
        if matches!(grant.subject, SubjectMatcher::Relation { .. }) && policy.relations.is_none() {
            report.error(
                &ids::field(&id, "subject"),
                "a relation subject needs relation blocks",
                Some("declare at least one `relation kind#name` block".into()),
            );
        }
        let Some(catalog) = catalog else { continue };
        let Some(def) = catalog.get(&grant.permission) else {
            report.error(
                &ids::field(&id, "permission"),
                format!("unknown permission `{}`", grant.permission),
                near(
                    &grant.permission,
                    permission_keys(policy),
                    Some("declare it as a permission block".into()),
                ),
            );
            continue;
        };
        if def.override_only {
            report.error(
                &ids::field(&id, "permission"),
                format!(
                    "`{}` holds only through an override and cannot be granted",
                    grant.permission
                ),
                None,
            );
        }
        let kind = grant.target.kind.as_str();
        if !catalog.is_broad_target(kind) && !def.targets.iter().any(|t| t == kind) {
            report.error(
                &ids::field(&id, "target"),
                format!("`{}` does not accept the target `{kind}`", grant.permission),
                Some(format!("accepted: {}", def.targets.join(", "))),
            );
        }
    }
}

/// A word the language reads back as one name: letters, digits and `_`, joined by `.` or `-`.
fn is_name(text: &str) -> bool {
    let mut previous_joiner = true;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            previous_joiner = false;
        } else if (c == '.' || c == '-') && !previous_joiner {
            previous_joiner = true;
        } else {
            return false;
        }
    }
    !previous_joiner
}

/// An attribute path is `subject.`, `resource.` or `env.` and a name.
pub(crate) fn is_attr_path(text: &str) -> bool {
    text.split_once('.')
        .is_some_and(|(root, rest)| matches!(root, "subject" | "resource" | "env") && is_name(rest))
}

fn operand_names(operand: &Operand, id: &str, report: &mut Report<'_>) {
    if let Operand::Attr { attr } = operand {
        attr_name(attr, id, report);
    }
}

fn attr_name(attr: &str, id: &str, report: &mut Report<'_>) {
    if !is_attr_path(attr) {
        report.error(
            id,
            format!("`{attr}` is not an attribute path"),
            Some("attributes start with subject., resource. or env. and are made of words".into()),
        );
    }
}

fn check_zone(tz: Option<&str>, id: &str, report: &mut Report<'_>) {
    let Some(name) = tz else { return };
    if let Err(reason) = crate::condition::check_tz(name) {
        report.error(
            id,
            reason,
            Some("write an IANA zone name, like \"America/Sao_Paulo\" or \"Europe/Lisbon\"".into()),
        );
    }
}

/// The names a condition uses: attribute paths and function names.
fn condition_names(condition: &Condition, id: &str, report: &mut Report<'_>) {
    match condition {
        Condition::Eq { left, right }
        | Condition::Ne { left, right }
        | Condition::Lt { left, right }
        | Condition::Le { left, right }
        | Condition::Gt { left, right }
        | Condition::Ge { left, right } => {
            operand_names(left, id, report);
            operand_names(right, id, report);
        }
        Condition::In { item, set } => {
            operand_names(item, id, report);
            operand_names(set, id, report);
        }
        Condition::StartsWith { left, right }
        | Condition::EndsWith { left, right }
        | Condition::Contains { left, right }
        | Condition::AnyIn { left, right }
        | Condition::AllIn { left, right } => {
            operand_names(left, id, report);
            operand_names(right, id, report);
        }
        Condition::IpIn { item, set } => {
            operand_names(item, id, report);
            operand_names(set, id, report);
            let texts: Vec<&str> = match set {
                Operand::Lit(Value::Str(text)) => vec![text.as_str()],
                Operand::Lit(Value::List(items)) => items.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for text in texts {
                if crate::condition::check_cidr(text).is_err() {
                    report.error(
                        id,
                        format!("`{text}` is not a CIDR block"),
                        Some("write an address and a prefix length, like \"10.0.0.0/8\" or \"2001:db8::/32\"".into()),
                    );
                }
            }
        }
        Condition::TimeBetween { from, until, tz } => {
            check_zone(tz.as_deref(), id, report);
            for text in [from, until] {
                if crate::condition::parse_clock(text).is_err() {
                    report.error(
                        id,
                        format!("`{text}` is not a time of day"),
                        Some("write hours and minutes with two digits each, 00:00 to 23:59, like \"09:30\"".into()),
                    );
                }
            }
        }
        Condition::WeekdayIn { days, tz } => {
            check_zone(tz.as_deref(), id, report);
            for day in days {
                if crate::condition::parse_weekday(day).is_err() {
                    report.error(
                        id,
                        format!("`{day}` is not a day of the week"),
                        Some("use mon, tue, wed, thu, fri, sat or sun, in lower case".into()),
                    );
                }
            }
        }
        Condition::Exists { attr } => attr_name(attr, id, report),
        Condition::All { of } | Condition::Any { of } => {
            for inner in of {
                condition_names(inner, id, report);
            }
        }
        Condition::Not { cond } => condition_names(cond, id, report),
        Condition::Call { func, args } => {
            if !is_name(func) {
                report.error(id, format!("`{func}` is not a function name"), None);
            }
            for arg in args {
                operand_names(arg, id, report);
            }
        }
    }
}

fn assignments(policy: &Policy, report: &mut Report<'_>) {
    let declared: BTreeSet<&str> = policy.roles.iter().map(|r| r.role.as_str()).collect();
    let mut subjects: HashSet<(&str, &str)> = HashSet::new();
    for subject in &policy.subjects {
        let Some(sid) = &subject.id else { continue };
        let subject_id = ids::subject(&subject.kind, sid);
        if !subjects.insert((&subject.kind, sid)) {
            report.error(
                &subject_id,
                format!("subject `{}:{sid}` is declared twice", subject.kind),
                None,
            );
        }
        let mut assigned: HashSet<&str> = HashSet::new();
        for RoleAssignment {
            role,
            valid_from,
            valid_until,
            ..
        } in &subject.roles
        {
            let id = ids::assign(&subject_id, role);
            if !assigned.insert(role) {
                report.error(&id, format!("the assignment of `{role}` is declared twice"), None);
            }
            if !declared.contains(role.as_str()) {
                report.error(
                    &id,
                    format!("role `{role}` is not declared"),
                    near(
                        role,
                        policy.roles.iter().map(|r| r.role.as_str()),
                        Some(format!("declare it with: role {role} {{ }}")),
                    ),
                );
            }
            if window_inverted(*valid_from, *valid_until) {
                report.error(
                    &ids::field(&id, "valid_until"),
                    "valid_until is not after valid_from",
                    None,
                );
            }
        }
    }
}

fn overrides(policy: &Policy, catalog: Option<&Catalog>, report: &mut Report<'_>) {
    let mut seen: HashSet<String> = HashSet::new();
    for spec in &policy.overrides {
        let id = match &spec.rule {
            OverrideRule::ResourceOwner { attr } => ids::override_owner(attr),
            OverrideRule::PermissionHolder { permission } => ids::override_holder(permission),
        };
        if !seen.insert(id.clone()) {
            report.error(&id, format!("`{id}` is declared twice"), None);
        }
        if let OverrideRule::ResourceOwner { attr } = &spec.rule
            && attr.contains('/')
        {
            report.error(
                &id,
                format!("`{attr}` is not an attribute name"),
                Some("it cannot hold `/`".into()),
            );
        }
        let Some(catalog) = catalog else { continue };
        let mut named: Vec<&String> = spec.except.iter().collect();
        if let OverrideRule::PermissionHolder { permission } = &spec.rule {
            named.push(permission);
        }
        for key in named {
            if !catalog.contains(key) {
                report.error(
                    &id,
                    format!("unknown permission `{key}`"),
                    near(key, permission_keys(policy), None),
                );
            }
        }
    }
}

fn invariants(policy: &Policy, catalog: Option<&Catalog>, report: &mut Report<'_>) {
    let declared: HashSet<&str> = policy.roles.iter().map(|r| r.role.as_str()).collect();
    let mut ordinals: HashMap<&'static str, usize> = HashMap::new();
    for spec in &policy.invariants {
        let kind = invariant_kind(spec);
        let ordinal = ordinals.entry(kind).or_insert(0);
        *ordinal += 1;
        let id = ids::invariant(kind, *ordinal);
        let mut permissions: Vec<&String> = Vec::new();
        match spec {
            InvariantSpec::RequirePermission { permission, .. } => permissions.push(permission),
            InvariantSpec::NoLockout { permissions: p, .. } | InvariantSpec::Forbid { permissions: p, .. } => {
                permissions.extend(p)
            }
            InvariantSpec::NoEscalation { bypass: Some(b) } => permissions.push(&b.permission),
            InvariantSpec::NonDelegable { manager } => permissions.push(manager),
            _ => {}
        }
        if let Some(catalog) = catalog {
            for key in permissions {
                if !catalog.contains(key) {
                    report.error(
                        &id,
                        format!("unknown permission `{key}`"),
                        near(key, permission_keys(policy), None),
                    );
                }
            }
        }
        match spec {
            InvariantSpec::NoEscalation { bypass: Some(b) } if b.resource.path.is_empty() => {
                report.error(
                    &id,
                    "the bypass needs a resource path",
                    Some("add a line: on = kind > kind:id".into()),
                );
            }
            InvariantSpec::ManagementOnly { roles } => {
                for role in roles {
                    if !declared.contains(role.as_str()) {
                        report.error(
                            &id,
                            format!("role `{role}` is not declared"),
                            near(role, policy.roles.iter().map(|r| r.role.as_str()), None),
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

/// The name of an invariant as the language spells it.
pub(crate) fn invariant_kind(spec: &InvariantSpec) -> &'static str {
    match spec {
        InvariantSpec::CatalogConformance => "catalog_conformance",
        InvariantSpec::NoSelfManagement => "no_self_management",
        InvariantSpec::RequirePermission { .. } => "require_permission",
        InvariantSpec::NoLockout { .. } => "no_lockout",
        InvariantSpec::Prerequisites => "prerequisites",
        InvariantSpec::NonDelegable { .. } => "non_delegable",
        InvariantSpec::ManagementOnly { .. } => "management_only",
        InvariantSpec::NoEscalation { .. } => "no_escalation",
        InvariantSpec::Forbid { .. } => "forbid",
    }
}
