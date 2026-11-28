//! AuthZEN entities to Strig ones. Nothing here decides: a request that cannot be mapped is an
//! error the caller turns into a `400` or a deny, never into a guess.

use serde::Deserialize;
use serde_json::Value as Json;
use strig::{AUTHENTICATED, Anchor, Attributes, Resource, RoleAssignment, Subject, Value};

use super::AuthzenConfig;
use super::wire::{Entity, Properties};

/// A request that does not fit the mapping. The text is fixed: it never echoes a value.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed(pub &'static str);

/// Why a resource could not be placed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResourceError {
    Malformed(Malformed),
    /// The server's resolver does not know it.
    Unknown,
}

impl From<Malformed> for ResourceError {
    fn from(error: Malformed) -> Self {
        Self::Malformed(error)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RoleItem {
    Name(String),
    Full(RoleAssignment),
}

fn required<'a>(value: &'a Option<String>, what: &'static str) -> Result<&'a str, Malformed> {
    match value.as_deref() {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(Malformed(what)),
    }
}

fn scalar(value: &Json) -> Option<Value> {
    Some(match value {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => n
            .as_i64()
            .map_or_else(|| n.as_f64().map(Value::Float), |i| Some(Value::Int(i)))?,
        Json::String(s) => Value::Str(s.clone()),
        Json::Array(_) | Json::Object(_) => return None,
    })
}

/// An attribute per leaf: nested objects flatten to dotted keys (`a.b`), arrays of scalars stay
/// lists. A key that two paths write, or an array with anything but scalars, is refused: Strig
/// attributes cannot say it, and dropping it could change a decision.
fn flatten(prefix: &str, value: &Json, out: &mut Attributes) -> Result<(), Malformed> {
    match value {
        Json::Object(map) => {
            for (key, inner) in map {
                let name = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&name, inner, out)?;
            }
            Ok(())
        }
        Json::Array(items) => {
            let list = items
                .iter()
                .map(scalar)
                .collect::<Option<Vec<_>>>()
                .ok_or(Malformed("an array attribute holds only scalars"))?;
            insert(out, prefix, Value::List(list))
        }
        leaf => insert(
            out,
            prefix,
            scalar(leaf).ok_or(Malformed("an attribute is not representable"))?,
        ),
    }
}

fn insert(out: &mut Attributes, key: &str, value: Value) -> Result<(), Malformed> {
    match out.insert(key.to_string(), value) {
        None => Ok(()),
        Some(_) => Err(Malformed("two properties write the same attribute")),
    }
}

/// `properties` or `context` as attributes, leaving out `reserved` (read by a convention).
fn attributes(properties: Option<&Properties>, reserved: &[&str]) -> Result<Attributes, Malformed> {
    let mut attrs = Attributes::new();
    for (key, value) in properties.into_iter().flatten() {
        if !reserved.contains(&key.as_str()) {
            flatten(key, value, &mut attrs)?;
        }
    }
    Ok(attrs)
}

pub(crate) fn env(context: Option<&Properties>) -> Result<Attributes, Malformed> {
    attributes(context, &[])
}

impl AuthzenConfig {
    /// A Subject: `type` is the kind, `id` the id; the roles and principals properties become
    /// roles and principals, every other property an attribute. The subject types in
    /// `authenticated_kinds` carry the `authenticated` principal.
    pub(crate) fn subject(&self, entity: &Entity) -> Result<Subject, Malformed> {
        if entity.kind.is_empty() {
            return Err(Malformed("the subject type is empty"));
        }
        let id = required(&entity.id, "the subject id is missing")?;
        let props = entity.properties.as_ref();
        let mut subject = Subject::of_kind(entity.kind.as_str(), id);
        if self.authenticated_kinds.contains(&entity.kind) {
            subject = subject.with_principal(AUTHENTICATED);
        }
        if let Some(Json::Array(items)) = props.and_then(|p| p.get(&self.roles_property)) {
            for item in items {
                subject = match RoleItem::deserialize(item)
                    .map_err(|_| Malformed("a role is not a name or an assignment"))?
                {
                    RoleItem::Name(name) => subject.with_role(name),
                    RoleItem::Full(assignment) => subject.with_assignment(assignment),
                };
            }
        } else if props.is_some_and(|p| p.contains_key(&self.roles_property)) {
            return Err(Malformed("the roles property is not an array"));
        }
        match props.and_then(|p| p.get(&self.principals_property)) {
            None => {}
            Some(Json::Array(items)) => {
                for item in items {
                    let name = item.as_str().ok_or(Malformed("a principal is not a string"))?;
                    subject = subject.with_principal(name);
                }
            }
            Some(_) => return Err(Malformed("the principals property is not an array")),
        }
        subject.attrs = attributes(props, &[&self.roles_property, &self.principals_property])?;
        Ok(subject)
    }

    /// A Resource: the first step of the path is `type:id`; the broader steps come from the
    /// server's resolver when there is one, otherwise from the `path` property (an array of
    /// `{kind, id?}`), otherwise there are none. Every other property is an attribute.
    pub(crate) fn resource(&self, entity: &Entity) -> Result<Resource, ResourceError> {
        if entity.kind.is_empty() {
            return Err(Malformed("the resource type is empty").into());
        }
        let id = required(&entity.id, "the resource id is missing")?;
        let props = entity.properties.as_ref();
        let mut resource = Resource::new(entity.kind.as_str(), id);
        let broader = if let Some(resolver) = &self.path_resolver {
            resolver.broader_steps(&entity.kind, id).ok_or(ResourceError::Unknown)?
        } else {
            match props.and_then(|p| p.get(&self.path_property)) {
                None => Vec::new(),
                Some(steps) => {
                    Vec::<Anchor>::deserialize(steps).map_err(|_| Malformed("the path is not an array of anchors"))?
                }
            }
        };
        resource.path.extend(broader);
        resource.attrs = attributes(props, &[&self.path_property])?;
        Ok(resource)
    }

    /// The entity a search leaves open: `type` is required, `id` is ignored if present.
    pub(crate) fn open_kind<'a>(&self, entity: &'a Entity, what: &'static str) -> Result<&'a str, Malformed> {
        if entity.kind.is_empty() {
            return Err(Malformed(what));
        }
        Ok(&entity.kind)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn entity(value: Json) -> Entity {
        serde_json::from_value(value).expect("entity")
    }

    #[test]
    fn properties_become_attributes_and_conventions_are_pulled_out() {
        let config = AuthzenConfig::default();
        let subject = config
            .subject(&entity(json!({
                "type": "user", "id": "alice",
                "properties": {
                    "department": "Sales",
                    "device": {"id": "d1", "managed": true},
                    "roles": ["editor", {"role": "owner", "scope": {"kind": "org", "id": "o1"}}],
                    "principals": ["staff"]
                }
            })))
            .expect("subject");
        assert_eq!(subject.attrs.get("department"), Some(&Value::Str("Sales".into())));
        assert_eq!(subject.attrs.get("device.managed"), Some(&Value::Bool(true)));
        assert!(!subject.attrs.contains_key("roles"));
        assert_eq!(subject.roles.len(), 2);
        assert_eq!(subject.roles[1].scope, Some(Anchor::new("org", "o1")));
        assert_eq!(subject.principals, ["authenticated", "staff"]);
    }

    #[test]
    fn what_cannot_be_said_in_attributes_is_refused() {
        let config = AuthzenConfig::default();
        let nested = entity(json!({"type": "user", "id": "a", "properties": {"x": [{"y": 1}]}}));
        assert!(config.subject(&nested).is_err());
        let clash = entity(json!({"type": "user", "id": "a", "properties": {"a.b": 1, "a": {"b": 2}}}));
        assert!(config.subject(&clash).is_err());
        let no_id = entity(json!({"type": "user"}));
        assert!(config.subject(&no_id).is_err());
        let bad_roles = entity(json!({"type": "user", "id": "a", "properties": {"roles": "admin"}}));
        assert!(config.subject(&bad_roles).is_err());
    }

    #[test]
    fn the_resource_path_comes_from_the_property() {
        let config = AuthzenConfig::default();
        let resource = config
            .resource(&entity(json!({
                "type": "document", "id": "d1",
                "properties": {"path": [{"kind": "org", "id": "o1"}], "owner": "bob"}
            })))
            .expect("resource");
        assert_eq!(resource.path, [Anchor::new("document", "d1"), Anchor::new("org", "o1")]);
        assert_eq!(resource.attrs.get("owner"), Some(&Value::Str("bob".into())));
        assert!(!resource.attrs.contains_key("path"));
    }
}
