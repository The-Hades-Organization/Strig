//! The validator: checks a whole policy, whatever syntax it came from, and says where each
//! problem is. It works on the real types, so a policy loaded from JSON is validated the same way
//! (without positions).

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::dsl::error::{Diagnostic, Location};
use crate::dsl::policy::{Origins, Policy, ids};
use crate::{Catalog, CatalogError, InvariantSpec, OverrideRule, Rewrite, RoleAssignment, SubjectMatcher};

struct Report<'a> {
    origins: Option<&'a Origins>,
    out: Vec<Diagnostic>,
}

impl Report<'_> {
    fn at(&self, id: &str) -> Option<Location> {
        self.origins.and_then(|o| o.get(id)).cloned()
    }

    fn error(&mut self, id: &str, message: impl Into<String>, hint: Option<String>) {
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
    };
    let catalog = catalog(policy, &mut report);
    roles(policy, &mut report);
    relations(policy, &mut report);
    grants(policy, catalog.as_ref(), &mut report);
    assignments(policy, &mut report);
    overrides(policy, catalog.as_ref(), &mut report);
    invariants(policy, catalog.as_ref(), &mut report);
    let mut out = report.out;
    out.sort_by_key(|d| d.location.as_ref().map(|at| (at.file.clone(), at.line, at.column)));
    out
}

fn catalog(policy: &Policy, report: &mut Report<'_>) -> Option<Catalog> {
    match Catalog::from_export(policy.catalog.clone()) {
        Ok(catalog) => Some(catalog),
        Err(errors) => {
            for error in errors.0 {
                catalog_error(error, report);
            }
            None
        }
    }
}

fn catalog_error(error: CatalogError, report: &mut Report<'_>) {
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
            hint("declare it or fix the name"),
        ),
        CatalogError::UnknownPrerequisite { key, prerequisite } => report.error(
            &format!("{}/depends_on/{prerequisite}", ids::permission(&key)),
            format!("`{key}` depends on `{prerequisite}`, which is not in the catalog"),
            hint("declare it or fix the name"),
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
            hint("add it to target_kinds"),
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
                    Some(format!("declare it with: role {parent} {{ }}")),
                );
            }
        }
    }
    let parents: HashMap<&str, Vec<&str>> = policy
        .roles
        .iter()
        .map(|r| (r.role.as_str(), r.inherits.iter().map(String::as_str).collect()))
        .collect();
    let mut reported: HashSet<&str> = HashSet::new();
    for role in &policy.roles {
        if let Some(path) = find_cycle(&role.role, &parents) {
            let head = path.first().copied().unwrap_or_default();
            if reported.insert(head) {
                report.error(
                    &ids::role(head),
                    format!("roles inherit in a cycle: {}", path.join(" -> ")),
                    None,
                );
            }
        }
    }
}

/// A path that starts and ends at `start` through `edges`, if there is one.
fn find_cycle<'a>(start: &'a str, edges: &HashMap<&'a str, Vec<&'a str>>) -> Option<Vec<&'a str>> {
    let mut path = vec![start];
    let mut visited: HashSet<&str> = HashSet::new();
    fn walk<'a>(
        node: &'a str,
        start: &'a str,
        edges: &HashMap<&'a str, Vec<&'a str>>,
        path: &mut Vec<&'a str>,
        visited: &mut HashSet<&'a str>,
    ) -> bool {
        for next in edges.get(node).into_iter().flatten() {
            if *next == start {
                path.push(start);
                return true;
            }
            if visited.insert(next) {
                path.push(next);
                if walk(next, start, edges, path, visited) {
                    return true;
                }
                path.pop();
            }
        }
        false
    }
    walk(start, start, edges, &mut path, &mut visited).then_some(path)
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
                Some("declare it as a permission block".into()),
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

fn assignments(policy: &Policy, report: &mut Report<'_>) {
    let declared: BTreeSet<&str> = policy.roles.iter().map(|r| r.role.as_str()).collect();
    for subject in &policy.subjects {
        let Some(sid) = &subject.id else { continue };
        let subject_id = ids::subject(&subject.kind, sid);
        for RoleAssignment {
            role,
            valid_from,
            valid_until,
            ..
        } in &subject.roles
        {
            let id = ids::assign(&subject_id, role);
            if !declared.contains(role.as_str()) {
                report.error(
                    &id,
                    format!("role `{role}` is not declared"),
                    Some(format!("declare it with: role {role} {{ }}")),
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
    for spec in &policy.overrides {
        let id = match &spec.rule {
            OverrideRule::ResourceOwner { attr } => ids::override_owner(attr),
            OverrideRule::PermissionHolder { permission } => ids::override_holder(permission),
        };
        let Some(catalog) = catalog else { continue };
        let mut named: Vec<&String> = spec.except.iter().collect();
        if let OverrideRule::PermissionHolder { permission } = &spec.rule {
            named.push(permission);
        }
        for key in named {
            if !catalog.contains(key) {
                report.error(&id, format!("unknown permission `{key}`"), None);
            }
        }
    }
}

fn invariants(policy: &Policy, catalog: Option<&Catalog>, report: &mut Report<'_>) {
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
                    report.error(&id, format!("unknown permission `{key}`"), None);
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
                    if !policy.roles.iter().any(|r| &r.role == role) {
                        report.error(&id, format!("role `{role}` is not declared"), None);
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
