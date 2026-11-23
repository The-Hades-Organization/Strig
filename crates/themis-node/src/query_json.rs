//! Os tipos de consulta da Themis em JSON. Os que o núcleo não serializa (`Expr`,
//! `FilterShape`, `SubjectRef`, ...) ganham aqui uma forma estável: `op` marca o nó de uma
//! expressão e `type` marca o formato de uma forma, de uma parte ou de um caminho.

use serde_json::{Value, json};
use themis::{AccessVia, Expr, FilterResidual, FilterShape, ObjectRef, SubjectRef};

use crate::error::{BindingError, BindingResult};
use crate::parse;

pub fn expr_json(expr: &Expr) -> Value {
    match expr {
        Expr::True => json!({"op": "true"}),
        Expr::False => json!({"op": "false"}),
        Expr::Within(anchor) => json!({"op": "within", "anchor": anchor}),
        Expr::OnPath(selector) => json!({"op": "on_path", "selector": selector}),
        Expr::AnchorIn { kind, ids } => json!({"op": "anchor_in", "kind": kind, "ids": ids}),
        Expr::AttrEq { attr, value } => json!({"op": "attr_eq", "attr": attr, "value": value}),
        Expr::Residual(index) => json!({"op": "residual", "index": index}),
        Expr::Not(inner) => json!({"op": "not", "expr": expr_json(inner)}),
        Expr::And(items) => json!({"op": "and", "exprs": items.iter().map(expr_json).collect::<Vec<_>>()}),
        Expr::Or(items) => json!({"op": "or", "exprs": items.iter().map(expr_json).collect::<Vec<_>>()}),
        // Um nó que este binding não conhece nunca vira permissão: é resíduo, a checar linha a linha.
        _ => json!({"op": "unknown"}),
    }
}

pub fn shape_json(shape: &FilterShape) -> Value {
    match shape {
        FilterShape::Nothing => json!({"type": "nothing"}),
        FilterShape::Kind { except } => json!({"type": "kind", "except": except}),
        FilterShape::Ids(ids) => json!({"type": "ids", "ids": ids}),
        FilterShape::Within(anchors) => json!({"type": "within", "anchors": anchors}),
        FilterShape::Compound(expr) => json!({"type": "compound", "expr": expr_json(expr)}),
        _ => json!({"type": "unknown"}),
    }
}

pub fn residual_json(residual: &FilterResidual) -> Value {
    match residual {
        FilterResidual::Condition { grant_id, condition } => {
            json!({"type": "condition", "grantId": grant_id, "condition": condition})
        }
        FilterResidual::Override { name } => json!({"type": "override", "name": name}),
        FilterResidual::Strategy { name } => json!({"type": "strategy", "name": name}),
        FilterResidual::OutsideLayout { grant_ids } => json!({"type": "outside_layout", "grantIds": grant_ids}),
        _ => json!({"type": "unknown"}),
    }
}

pub fn subject_ref_json(subject: &SubjectRef) -> Value {
    match subject {
        SubjectRef::User { id } => json!({"type": "user", "id": id}),
        SubjectRef::Object { kind, id } => json!({"type": "object", "kind": kind, "id": id}),
        SubjectRef::Role { id } => json!({"type": "role", "id": id}),
        SubjectRef::Principal { name } => json!({"type": "principal", "name": name}),
        SubjectRef::Userset { object, relation } => json!({"type": "userset", "object": object, "relation": relation}),
        SubjectRef::Wildcard { kind } => json!({"type": "wildcard", "kind": kind}),
        SubjectRef::Anyone => json!({"type": "anyone"}),
        _ => json!({"type": "unknown"}),
    }
}

/// Lê um `SubjectRef` na mesma forma que `subject_ref_json` escreve.
pub fn parse_subject_ref(value: Value) -> BindingResult<SubjectRef> {
    let field = |name: &str| -> BindingResult<String> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| BindingError::invalid_input("subject ref", format!("falta `{name}`")))
    };
    match value.get("type").and_then(Value::as_str) {
        Some("user") => Ok(SubjectRef::User { id: field("id")? }),
        Some("object") => Ok(SubjectRef::Object {
            kind: field("kind")?,
            id: field("id")?,
        }),
        Some("role") => Ok(SubjectRef::Role { id: field("id")? }),
        Some("principal") => Ok(SubjectRef::Principal { name: field("name")? }),
        Some("userset") => Ok(SubjectRef::Userset {
            object: parse::<ObjectRef>("subject ref", value.get("object").cloned().unwrap_or(Value::Null))?,
            relation: field("relation")?,
        }),
        Some("wildcard") => Ok(SubjectRef::Wildcard { kind: field("kind")? }),
        Some("anyone") => Ok(SubjectRef::Anyone),
        other => Err(BindingError::invalid_input(
            "subject ref",
            format!("`type` desconhecido: {other:?}"),
        )),
    }
}

pub fn via_json(via: &AccessVia) -> Value {
    match via {
        AccessVia::Override { name } => json!({"type": "override", "name": name}),
        AccessVia::Grant { grant_id } => json!({"type": "grant", "grantId": grant_id}),
        AccessVia::Role { grant_id, role } => json!({"type": "role", "grantId": grant_id, "role": role}),
        AccessVia::InheritedRole { grant_id, role, from } => {
            json!({"type": "inherited_role", "grantId": grant_id, "role": role, "from": from})
        }
        AccessVia::Relation {
            grant_id,
            relation,
            object,
        } => json!({"type": "relation", "grantId": grant_id, "relation": relation, "object": object}),
        AccessVia::Nothing => json!({"type": "nothing"}),
        _ => json!({"type": "unknown"}),
    }
}
