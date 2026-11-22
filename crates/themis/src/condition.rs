use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::attr::{Attributes, Value};
use crate::resource::Resource;
use crate::subject::Subject;

/// One side of a comparison: an attribute resolved at decision time or a literal.
///
/// Attributes use the path `<root>.<name>`, with root `subject`, `resource` or `env`.
/// `subject.id`, `subject.kind`, `resource.id` and `resource.kind` come from the identity; the
/// rest comes from the attribute map.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Operand {
    Attr { attr: String },
    Lit(Value),
}

impl Operand {
    pub fn attr(path: impl Into<String>) -> Self {
        Self::Attr { attr: path.into() }
    }

    pub fn lit(value: impl Into<Value>) -> Self {
        Self::Lit(value.into())
    }
}

/// Serializable ABAC condition, stored together with the grant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Condition {
    Eq {
        left: Operand,
        right: Operand,
    },
    Ne {
        left: Operand,
        right: Operand,
    },
    Lt {
        left: Operand,
        right: Operand,
    },
    Le {
        left: Operand,
        right: Operand,
    },
    Gt {
        left: Operand,
        right: Operand,
    },
    Ge {
        left: Operand,
        right: Operand,
    },
    /// `item` belongs to the list `set`.
    In {
        item: Operand,
        set: Operand,
    },
    /// The attribute exists.
    Exists {
        attr: String,
    },
    All {
        of: Vec<Condition>,
    },
    Any {
        of: Vec<Condition>,
    },
    Not {
        cond: Box<Condition>,
    },
    /// Function registered in the engine's [`ConditionRegistry`].
    Call {
        func: String,
        #[serde(default)]
        args: Vec<Operand>,
    },
}

impl Condition {
    pub fn eq(left: Operand, right: Operand) -> Self {
        Self::Eq { left, right }
    }

    pub fn ne(left: Operand, right: Operand) -> Self {
        Self::Ne { left, right }
    }

    pub fn lt(left: Operand, right: Operand) -> Self {
        Self::Lt { left, right }
    }

    pub fn le(left: Operand, right: Operand) -> Self {
        Self::Le { left, right }
    }

    pub fn gt(left: Operand, right: Operand) -> Self {
        Self::Gt { left, right }
    }

    pub fn ge(left: Operand, right: Operand) -> Self {
        Self::Ge { left, right }
    }

    pub fn is_in(item: Operand, set: Operand) -> Self {
        Self::In { item, set }
    }

    pub fn exists(attr: impl Into<String>) -> Self {
        Self::Exists { attr: attr.into() }
    }

    pub fn all(of: impl IntoIterator<Item = Condition>) -> Self {
        Self::All {
            of: of.into_iter().collect(),
        }
    }

    pub fn any(of: impl IntoIterator<Item = Condition>) -> Self {
        Self::Any {
            of: of.into_iter().collect(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn not(cond: Condition) -> Self {
        Self::Not { cond: Box::new(cond) }
    }

    pub fn call(func: impl Into<String>, args: impl IntoIterator<Item = Operand>) -> Self {
        Self::Call {
            func: func.into(),
            args: args.into_iter().collect(),
        }
    }

    /// Names of the functions used, to validate against the registry before writing the grant.
    pub fn functions(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.collect_functions(&mut out);
        out
    }

    fn collect_functions<'a>(&'a self, out: &mut Vec<&'a str>) {
        match self {
            Condition::Call { func, .. } => out.push(func),
            Condition::All { of } | Condition::Any { of } => of.iter().for_each(|c| c.collect_functions(out)),
            Condition::Not { cond } => cond.collect_functions(out),
            _ => {}
        }
    }

    pub fn evaluate(&self, ctx: &EvalContext<'_>, registry: &ConditionRegistry) -> Result<bool, ConditionError> {
        match self {
            Condition::Eq { left, right } => Ok(ctx.operand(left)?.loosely_eq(&ctx.operand(right)?)),
            Condition::Ne { left, right } => Ok(!ctx.operand(left)?.loosely_eq(&ctx.operand(right)?)),
            Condition::Lt { left, right } => ctx.order("lt", left, right, |o| o == Ordering::Less),
            Condition::Le { left, right } => ctx.order("le", left, right, |o| o != Ordering::Greater),
            Condition::Gt { left, right } => ctx.order("gt", left, right, |o| o == Ordering::Greater),
            Condition::Ge { left, right } => ctx.order("ge", left, right, |o| o != Ordering::Less),
            Condition::In { item, set } => match ctx.operand(set)? {
                Value::List(values) => {
                    let item = ctx.operand(item)?;
                    Ok(values.iter().any(|v| v.loosely_eq(&item)))
                }
                _ => Err(ConditionError::TypeMismatch(
                    "in: o conjunto precisa ser lista".to_string(),
                )),
            },
            Condition::Exists { attr } => Ok(ctx.resolve(attr)?.is_some()),
            Condition::All { of } => {
                for cond in of {
                    if !cond.evaluate(ctx, registry)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::Any { of } => {
                for cond in of {
                    if cond.evaluate(ctx, registry)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Condition::Not { cond } => Ok(!cond.evaluate(ctx, registry)?),
            Condition::Call { func, args } => {
                let f = registry
                    .get(func)
                    .ok_or_else(|| ConditionError::UnknownFunction(func.clone()))?;
                let values = args.iter().map(|a| ctx.operand(a)).collect::<Result<Vec<_>, _>>()?;
                f(&values)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConditionError {
    #[error("atributo ausente: {0}")]
    MissingAttribute(String),
    #[error("caminho de atributo inválido: {0}")]
    BadPath(String),
    #[error("tipos incompatíveis: {0}")]
    TypeMismatch(String),
    #[error("função não registrada: {0}")]
    UnknownFunction(String),
    #[error("{0}")]
    Function(String),
}

/// What a condition sees during the decision.
#[derive(Clone, Copy)]
pub struct EvalContext<'a> {
    pub subject: &'a Subject,
    pub resource: &'a Resource,
    pub env: &'a Attributes,
}

impl EvalContext<'_> {
    pub fn resolve(&self, path: &str) -> Result<Option<Value>, ConditionError> {
        let (root, name) = path
            .split_once('.')
            .ok_or_else(|| ConditionError::BadPath(path.to_string()))?;
        let value = match (root, name) {
            ("subject", "id") => self.subject.id.clone().map(Value::Str),
            ("subject", "kind") => Some(Value::Str(self.subject.kind.clone())),
            ("subject", _) => self.subject.attrs.get(name).cloned(),
            ("resource", "id") => self.resource.primary().and_then(|a| a.id.clone()).map(Value::Str),
            ("resource", "kind") => self.resource.primary().map(|a| Value::Str(a.kind.clone())),
            ("resource", _) => self.resource.attrs.get(name).cloned(),
            ("env", _) => self.env.get(name).cloned(),
            _ => return Err(ConditionError::BadPath(path.to_string())),
        };
        Ok(value)
    }

    fn operand(&self, operand: &Operand) -> Result<Value, ConditionError> {
        match operand {
            Operand::Lit(value) => Ok(value.clone()),
            Operand::Attr { attr } => self
                .resolve(attr)?
                .ok_or_else(|| ConditionError::MissingAttribute(attr.clone())),
        }
    }

    fn order(
        &self,
        op: &str,
        left: &Operand,
        right: &Operand,
        accept: impl Fn(Ordering) -> bool,
    ) -> Result<bool, ConditionError> {
        let (l, r) = (self.operand(left)?, self.operand(right)?);
        l.compare(&r)
            .map(accept)
            .ok_or_else(|| ConditionError::TypeMismatch(format!("{op}: {l:?} e {r:?} não se comparam")))
    }
}

pub type ConditionFn = Arc<dyn Fn(&[Value]) -> Result<bool, ConditionError> + Send + Sync>;

/// Functions that conditions can call by name. ABAC extension point.
#[derive(Clone, Default)]
pub struct ConditionRegistry {
    fns: HashMap<String, ConditionFn>,
}

impl ConditionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        mut self,
        name: impl Into<String>,
        f: impl Fn(&[Value]) -> Result<bool, ConditionError> + Send + Sync + 'static,
    ) -> Self {
        self.fns.insert(name.into(), Arc::new(f));
        self
    }

    pub fn get(&self, name: &str) -> Option<&ConditionFn> {
        self.fns.get(name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.fns.contains_key(name)
    }
}

impl fmt::Debug for ConditionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names: Vec<_> = self.fns.keys().collect();
        names.sort();
        f.debug_struct("ConditionRegistry").field("fns", &names).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(
        cond: &Condition,
        subject: &Subject,
        resource: &Resource,
        env: &Attributes,
    ) -> Result<bool, ConditionError> {
        let registry = ConditionRegistry::new().register("starts_with", |args| match args {
            [Value::Str(s), Value::Str(prefix)] => Ok(s.starts_with(prefix.as_str())),
            _ => Err(ConditionError::Function("starts_with(str, str)".to_string())),
        });
        cond.evaluate(&EvalContext { subject, resource, env }, &registry)
    }

    #[test]
    fn compares_subject_and_resource_attributes() {
        let s = Subject::user("u").with_attr("clearance", 3);
        let r = Resource::new("doc", "d").with_attr("level", 2);
        let cond = Condition::ge(Operand::attr("subject.clearance"), Operand::attr("resource.level"));
        assert!(eval(&cond, &s, &r, &Attributes::new()).unwrap());
    }

    #[test]
    fn missing_attribute_is_an_error_but_exists_is_false() {
        let s = Subject::user("u");
        let r = Resource::new("doc", "d");
        let env = Attributes::new();
        let cond = Condition::eq(Operand::attr("subject.dept"), Operand::lit("eng"));
        assert_eq!(
            eval(&cond, &s, &r, &env),
            Err(ConditionError::MissingAttribute("subject.dept".to_string()))
        );
        assert!(!eval(&Condition::exists("subject.dept"), &s, &r, &env).unwrap());
    }

    #[test]
    fn in_and_custom_function() {
        let s = Subject::user("u").with_attr("dept", "eng");
        let r = Resource::new("doc", "draft-1");
        let mut env = Attributes::new();
        env.insert("depts".to_string(), Value::from(vec!["eng", "ops"]));
        let cond = Condition::all([
            Condition::is_in(Operand::attr("subject.dept"), Operand::attr("env.depts")),
            Condition::call("starts_with", [Operand::attr("resource.id"), Operand::lit("draft")]),
        ]);
        assert!(eval(&cond, &s, &r, &env).unwrap());
        assert_eq!(cond.functions(), ["starts_with"]);
    }

    #[test]
    fn json_shape() {
        let cond: Condition = serde_json::from_str(
            r#"{"op":"any","of":[{"op":"eq","left":{"attr":"subject.id"},"right":"alice"},{"op":"not","cond":{"op":"exists","attr":"resource.locked"}}]}"#,
        )
        .unwrap();
        let s = Subject::user("bob");
        assert!(eval(&cond, &s, &Resource::new("doc", "d"), &Attributes::new()).unwrap());
    }
}
