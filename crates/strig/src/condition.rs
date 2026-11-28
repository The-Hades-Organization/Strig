use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
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
#[non_exhaustive]
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
#[non_exhaustive]
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
    /// Text `left` starts with text `right`.
    StartsWith {
        left: Operand,
        right: Operand,
    },
    /// Text `left` ends with text `right`.
    EndsWith {
        left: Operand,
        right: Operand,
    },
    /// Text `left` contains text `right` as a substring, or list `left` has `right` as an element.
    Contains {
        left: Operand,
        right: Operand,
    },
    /// The list `left` has at least one element that belongs to the list `right`.
    AnyIn {
        left: Operand,
        right: Operand,
    },
    /// Every element of the list `left` belongs to the list `right`; an empty `left` holds.
    AllIn {
        left: Operand,
        right: Operand,
    },
    /// The IPv4 or IPv6 address `item` lies inside the CIDR `set`, or inside one of the CIDRs of
    /// the list `set`. An address without a prefix length stands for a single host.
    IpIn {
        item: Operand,
        set: Operand,
    },
    /// The time of day of the decision instant is in `[from, until)`, both as `HH:MM`. A window
    /// with `from` after `until` crosses midnight; equal bounds make an empty window. The clock is
    /// UTC, or the wall clock of the IANA zone `tz` (`America/Sao_Paulo`); see [`Condition::in_tz`].
    TimeBetween {
        from: String,
        until: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tz: Option<String>,
    },
    /// The weekday of the decision instant is one of `days` (`mon` to `sun`), in UTC or in the
    /// zone `tz`.
    WeekdayIn {
        days: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tz: Option<String>,
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

    pub fn starts_with(left: Operand, right: Operand) -> Self {
        Self::StartsWith { left, right }
    }

    pub fn ends_with(left: Operand, right: Operand) -> Self {
        Self::EndsWith { left, right }
    }

    pub fn contains(left: Operand, right: Operand) -> Self {
        Self::Contains { left, right }
    }

    pub fn any_in(left: Operand, right: Operand) -> Self {
        Self::AnyIn { left, right }
    }

    pub fn all_in(left: Operand, right: Operand) -> Self {
        Self::AllIn { left, right }
    }

    pub fn ip_in(item: Operand, set: Operand) -> Self {
        Self::IpIn { item, set }
    }

    pub fn time_between(from: impl Into<String>, until: impl Into<String>) -> Self {
        Self::TimeBetween {
            from: from.into(),
            until: until.into(),
            tz: None,
        }
    }

    pub fn weekday_in<S: Into<String>>(days: impl IntoIterator<Item = S>) -> Self {
        Self::WeekdayIn {
            days: days.into_iter().map(Into::into).collect(),
            tz: None,
        }
    }

    /// True when this condition, or one nested in it, names a time zone.
    pub fn uses_tz(&self) -> bool {
        match self {
            Self::TimeBetween { tz, .. } | Self::WeekdayIn { tz, .. } => tz.is_some(),
            Self::All { of } | Self::Any { of } => of.iter().any(Self::uses_tz),
            Self::Not { cond } => cond.uses_tz(),
            _ => false,
        }
    }

    /// Reads the clock of an IANA zone (`America/Sao_Paulo`) instead of UTC in `time_between` and
    /// `weekday_in`; any other condition is returned as it is. An unknown name is refused when a
    /// policy is loaded and fails the evaluation here.
    ///
    /// The instant decides the local time, so a clock change never leaves a time ambiguous: in the
    /// hour skipped by the spring-forward jump no instant has that local time, so a window that
    /// lies wholly inside it never holds that day; in the hour repeated by the fall-back both
    /// passes hold.
    pub fn in_tz(mut self, zone: impl Into<String>) -> Self {
        if let Self::TimeBetween { tz, .. } | Self::WeekdayIn { tz, .. } = &mut self {
            *tz = Some(zone.into());
        }
        self
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

    /// Evaluates without a decision instant: the time conditions fail with a missing `now`.
    pub fn evaluate(&self, ctx: &EvalContext<'_>, registry: &ConditionRegistry) -> Result<bool, ConditionError> {
        self.evaluate_at(ctx, registry, None)
    }

    /// Evaluates at `now`, in milliseconds since the Unix epoch, the instant that `time_between` and
    /// `weekday_in` read, always in UTC. The core reads no clock; without an instant those two fail
    /// with [`ConditionError::MissingAttribute`], so an `allow` they guard does not apply.
    pub fn evaluate_at(
        &self,
        ctx: &EvalContext<'_>,
        registry: &ConditionRegistry,
        now: Option<u64>,
    ) -> Result<bool, ConditionError> {
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
            Condition::StartsWith { left, right } => ctx.text("starts_with", left, right, |t, p| t.starts_with(p)),
            Condition::EndsWith { left, right } => ctx.text("ends_with", left, right, |t, p| t.ends_with(p)),
            Condition::Contains { left, right } => match ctx.operand(left)? {
                Value::List(values) => {
                    let item = ctx.operand(right)?;
                    Ok(values.iter().any(|v| v.loosely_eq(&item)))
                }
                Value::Str(text) => match ctx.operand(right)? {
                    Value::Str(part) => Ok(text.contains(part.as_str())),
                    other => Err(ConditionError::TypeMismatch(format!(
                        "contains: texto só contém texto, veio {other:?}"
                    ))),
                },
                other => Err(ConditionError::TypeMismatch(format!(
                    "contains: o lado esquerdo precisa ser texto ou lista, veio {other:?}"
                ))),
            },
            Condition::AnyIn { left, right } => {
                let (items, set) = ctx.lists("any_in", left, right)?;
                Ok(items.iter().any(|i| set.iter().any(|v| v.loosely_eq(i))))
            }
            Condition::AllIn { left, right } => {
                let (items, set) = ctx.lists("all_in", left, right)?;
                Ok(items.iter().all(|i| set.iter().any(|v| v.loosely_eq(i))))
            }
            Condition::IpIn { item, set } => {
                let addr = match ctx.operand(item)? {
                    Value::Str(text) => parse_addr(&text)?,
                    other => {
                        return Err(ConditionError::TypeMismatch(format!(
                            "ip_in: o endereço precisa ser texto, veio {other:?}"
                        )));
                    }
                };
                match ctx.operand(set)? {
                    Value::Str(cidr) => Ok(Cidr::parse(&cidr)?.contains(addr)),
                    Value::List(values) => {
                        for value in &values {
                            let Value::Str(cidr) = value else {
                                return Err(ConditionError::TypeMismatch(format!(
                                    "ip_in: CIDR precisa ser texto, veio {value:?}"
                                )));
                            };
                            if Cidr::parse(cidr)?.contains(addr) {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    }
                    other => Err(ConditionError::TypeMismatch(format!(
                        "ip_in: o conjunto precisa ser CIDR ou lista de CIDRs, veio {other:?}"
                    ))),
                }
            }
            Condition::TimeBetween { from, until, tz } => {
                let (from, until) = (parse_clock(from)?, parse_clock(until)?);
                let at = local_time(now, tz.as_deref())?.minute;
                Ok(if from <= until {
                    from <= at && at < until
                } else {
                    at >= from || at < until
                })
            }
            Condition::WeekdayIn { days, tz } => {
                let today = local_time(now, tz.as_deref())?.weekday;
                for day in days {
                    if parse_weekday(day)? == today {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Condition::Exists { attr } => Ok(ctx.resolve(attr)?.is_some()),
            Condition::All { of } => {
                for cond in of {
                    if !cond.evaluate_at(ctx, registry, now)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Condition::Any { of } => {
                for cond in of {
                    if cond.evaluate_at(ctx, registry, now)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Condition::Not { cond } => Ok(!cond.evaluate_at(ctx, registry, now)?),
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
#[non_exhaustive]
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

    fn text(
        &self,
        op: &str,
        left: &Operand,
        right: &Operand,
        test: impl Fn(&str, &str) -> bool,
    ) -> Result<bool, ConditionError> {
        match (self.operand(left)?, self.operand(right)?) {
            (Value::Str(l), Value::Str(r)) => Ok(test(&l, &r)),
            (l, r) => Err(ConditionError::TypeMismatch(format!(
                "{op}: {l:?} e {r:?} precisam ser texto"
            ))),
        }
    }

    fn lists(&self, op: &str, left: &Operand, right: &Operand) -> Result<(Vec<Value>, Vec<Value>), ConditionError> {
        match (self.operand(left)?, self.operand(right)?) {
            (Value::List(l), Value::List(r)) => Ok((l, r)),
            (l, r) => Err(ConditionError::TypeMismatch(format!(
                "{op}: {l:?} e {r:?} precisam ser listas"
            ))),
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

fn bad_value(what: &str, text: &str) -> ConditionError {
    ConditionError::TypeMismatch(format!("{what} inválido: {text:?}"))
}

/// An address with an IPv4-mapped IPv6 form read as the IPv4 address it wraps.
fn parse_addr(text: &str) -> Result<IpAddr, ConditionError> {
    text.parse::<IpAddr>()
        .map(|a| a.to_canonical())
        .map_err(|_| bad_value("endereço IP", text))
}

/// A CIDR block, normalized so that IPv4 and its IPv4-mapped IPv6 spelling are the same block.
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Result<Self, ConditionError> {
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| bad_value("CIDR", text))?;
        let max: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| bad_value("CIDR", text))?,
        };
        // `::ffff:a.b.c.d/n` with n >= 96 is the IPv4 block `a.b.c.d/(n - 96)`.
        if let IpAddr::V6(v6) = addr
            && prefix >= 96
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            return Ok(Self {
                network: IpAddr::V4(v4),
                prefix: prefix - 96,
            });
        }
        Ok(Self { network: addr, prefix })
    }

    fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.prefix)).unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.prefix)).unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Checks a CIDR block, for the language to refuse a literal one before any decision.
#[cfg(feature = "dsl")]
pub(crate) fn check_cidr(text: &str) -> Result<(), ConditionError> {
    Cidr::parse(text).map(|_| ())
}

/// Minutes since midnight of an `HH:MM` clock time.
pub(crate) fn parse_clock(text: &str) -> Result<u32, ConditionError> {
    let parsed = text.split_once(':').and_then(|(h, m)| {
        let digits = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit());
        if !digits(h) || !digits(m) {
            return None;
        }
        let (h, m) = (h.parse::<u32>().ok()?, m.parse::<u32>().ok()?);
        (h < 24 && m < 60).then_some(h * 60 + m)
    });
    parsed.ok_or_else(|| bad_value("horário (use HH:MM)", text))
}

/// Day of the week, 0 for Monday.
pub(crate) fn parse_weekday(text: &str) -> Result<u8, ConditionError> {
    const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    DAYS.iter()
        .position(|d| *d == text)
        .and_then(|i| u8::try_from(i).ok())
        .ok_or_else(|| bad_value("dia da semana (mon a sun)", text))
}

const MS_PER_MINUTE: i64 = 60_000;
const MS_PER_DAY: i64 = 86_400_000;

/// The wall clock of an instant: minutes since local midnight and weekday (0 = Monday).
pub(crate) struct LocalTime {
    pub(crate) minute: u32,
    pub(crate) weekday: u8,
    offset_seconds: i64,
}

impl LocalTime {
    /// `09:30 UTC` or `06:30 America/Sao_Paulo (UTC-03:00)`, for the trace.
    pub(crate) fn describe(&self, tz: Option<&str>) -> String {
        let clock = format!("{:02}:{:02}", self.minute / 60, self.minute % 60);
        let Some(zone) = tz else {
            return format!("{clock} UTC");
        };
        let sign = if self.offset_seconds < 0 { '-' } else { '+' };
        let minutes = self.offset_seconds.abs() / 60;
        format!("{clock} {zone} (UTC{sign}{:02}:{:02})", minutes / 60, minutes % 60)
    }
}

/// The clock a time condition reads, for the trace: the zone alone, or with the local time of `now`.
pub(crate) fn clock_label(now: Option<u64>, tz: Option<&str>, weekday: bool) -> String {
    let zone = tz.unwrap_or("UTC");
    let Some(local) = now.and_then(|now| local_time(Some(now), tz).ok()) else {
        return zone.to_string();
    };
    if weekday {
        const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
        return format!("{zone} ({})", DAYS[usize::from(local.weekday)]);
    }
    local.describe(tz)
}

/// Whether `name` is a zone the engine can read; the message is fit for a diagnostic.
#[cfg_attr(
    not(feature = "dsl"),
    allow(dead_code, reason = "only the policy language checks zones at load")
)]
pub(crate) fn check_tz(name: &str) -> Result<(), String> {
    zone_offset(name, 0).map(|_| ())
}

#[cfg(feature = "tz")]
fn zone_offset(name: &str, now_ms: u64) -> Result<i64, String> {
    use chrono::{DateTime, Offset, TimeZone};
    use chrono_tz::Tz;
    let zone: Tz = name
        .parse()
        .map_err(|_| format!("`{name}` is not an IANA time zone name"))?;
    let instant = i64::try_from(now_ms)
        .ok()
        .and_then(DateTime::from_timestamp_millis)
        .ok_or_else(|| "the decision instant is out of range".to_string())?;
    let offset = zone.offset_from_utc_datetime(&instant.naive_utc()).fix();
    Ok(i64::from(offset.local_minus_utc()))
}

#[cfg(not(feature = "tz"))]
fn zone_offset(name: &str, _now_ms: u64) -> Result<i64, String> {
    Err(format!("`{name}`: this build has no time zone database (feature `tz`)"))
}

fn local_time(now: Option<u64>, tz: Option<&str>) -> Result<LocalTime, ConditionError> {
    let now = now.ok_or_else(|| ConditionError::MissingAttribute("now".to_string()))?;
    let offset_seconds = match tz {
        None => 0,
        Some(name) => zone_offset(name, now).map_err(ConditionError::Function)?,
    };
    let local = i64::try_from(now)
        .map_err(|_| ConditionError::BadPath("now".to_string()))?
        .saturating_add(offset_seconds * 1_000);
    let (day, in_day) = (local.div_euclid(MS_PER_DAY), local.rem_euclid(MS_PER_DAY));
    Ok(LocalTime {
        minute: u32::try_from(in_day / MS_PER_MINUTE).map_err(|_| ConditionError::BadPath("now".to_string()))?,
        // Day 0 of the epoch, 1970-01-01, was a Thursday.
        weekday: u8::try_from((day + 3).rem_euclid(7)).map_err(|_| ConditionError::BadPath("now".to_string()))?,
        offset_seconds,
    })
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

    // ---- string, set, network and time conditions ----

    fn lit(v: impl Into<Value>) -> Operand {
        Operand::lit(v)
    }

    fn holds(cond: &Condition) -> Result<bool, ConditionError> {
        let (s, r) = (Subject::user("u"), Resource::new("doc", "d"));
        cond.evaluate(
            &EvalContext {
                subject: &s,
                resource: &r,
                env: &Attributes::new(),
            },
            &ConditionRegistry::new(),
        )
    }

    fn holds_at(cond: &Condition, now: u64) -> Result<bool, ConditionError> {
        let (s, r) = (Subject::user("u"), Resource::new("doc", "d"));
        cond.evaluate_at(
            &EvalContext {
                subject: &s,
                resource: &r,
                env: &Attributes::new(),
            },
            &ConditionRegistry::new(),
            Some(now),
        )
    }

    fn is_mismatch(r: Result<bool, ConditionError>) -> bool {
        matches!(r, Err(ConditionError::TypeMismatch(_)))
    }

    #[test]
    fn text_conditions_match_prefix_suffix_and_substring() {
        assert_eq!(holds(&Condition::starts_with(lit("draft-1"), lit("draft"))), Ok(true));
        assert_eq!(holds(&Condition::starts_with(lit("draft-1"), lit("final"))), Ok(false));
        assert_eq!(holds(&Condition::ends_with(lit("a.pdf"), lit(".pdf"))), Ok(true));
        assert_eq!(holds(&Condition::ends_with(lit("a.pdf"), lit(".txt"))), Ok(false));
        assert_eq!(holds(&Condition::contains(lit("a-b-c"), lit("-b-"))), Ok(true));
        assert_eq!(holds(&Condition::contains(lit("abc"), lit("x"))), Ok(false));
    }

    #[test]
    fn text_conditions_treat_the_empty_text_as_prefix_suffix_and_substring_of_everything() {
        assert_eq!(holds(&Condition::starts_with(lit("abc"), lit(""))), Ok(true));
        assert_eq!(holds(&Condition::ends_with(lit("abc"), lit(""))), Ok(true));
        assert_eq!(holds(&Condition::contains(lit("abc"), lit(""))), Ok(true));
        assert_eq!(holds(&Condition::starts_with(lit(""), lit("a"))), Ok(false));
        assert_eq!(holds(&Condition::contains(lit(""), lit(""))), Ok(true));
    }

    #[test]
    fn text_conditions_reject_operands_that_are_not_text() {
        assert!(is_mismatch(holds(&Condition::starts_with(lit(1), lit("a")))));
        assert!(is_mismatch(holds(&Condition::ends_with(lit("a"), lit(true)))));
        assert!(is_mismatch(holds(&Condition::contains(lit("a"), lit(1)))));
        assert!(is_mismatch(holds(&Condition::contains(lit(1), lit(1)))));
    }

    #[test]
    fn contains_on_a_list_is_membership_with_loose_numbers() {
        let list = lit(Value::from(vec!["a", "b"]));
        assert_eq!(holds(&Condition::contains(list.clone(), lit("b"))), Ok(true));
        assert_eq!(holds(&Condition::contains(list, lit("c"))), Ok(false));
        let nums = lit(Value::List(vec![Value::Int(1), Value::Int(2)]));
        assert_eq!(holds(&Condition::contains(nums, lit(2.0))), Ok(true));
        assert_eq!(
            holds(&Condition::contains(lit(Value::List(vec![])), lit("a"))),
            Ok(false)
        );
    }

    #[test]
    fn missing_attribute_in_a_new_condition_is_an_error() {
        let cond = Condition::contains(Operand::attr("subject.tags"), lit("a"));
        assert_eq!(
            holds(&cond),
            Err(ConditionError::MissingAttribute("subject.tags".to_string()))
        );
    }

    #[test]
    fn any_in_needs_one_common_element() {
        let set = lit(Value::from(vec!["a", "b"]));
        assert_eq!(
            holds(&Condition::any_in(lit(Value::from(vec!["x", "b"])), set.clone())),
            Ok(true)
        );
        assert_eq!(
            holds(&Condition::any_in(lit(Value::from(vec!["x", "y"])), set.clone())),
            Ok(false)
        );
        assert_eq!(
            holds(&Condition::any_in(lit(Value::List(vec![])), set.clone())),
            Ok(false)
        );
        assert_eq!(
            holds(&Condition::any_in(
                lit(Value::from(vec!["a"])),
                lit(Value::List(vec![]))
            )),
            Ok(false)
        );
        assert!(is_mismatch(holds(&Condition::any_in(lit("a"), set))));
    }

    #[test]
    fn all_in_needs_every_element_and_an_empty_list_holds() {
        let set = lit(Value::from(vec!["a", "b"]));
        assert_eq!(
            holds(&Condition::all_in(lit(Value::from(vec!["a", "b"])), set.clone())),
            Ok(true)
        );
        assert_eq!(
            holds(&Condition::all_in(lit(Value::from(vec!["a", "x"])), set.clone())),
            Ok(false)
        );
        assert_eq!(
            holds(&Condition::all_in(lit(Value::List(vec![])), set.clone())),
            Ok(true)
        );
        assert_eq!(
            holds(&Condition::all_in(
                lit(Value::from(vec!["a"])),
                lit(Value::List(vec![]))
            )),
            Ok(false)
        );
        assert!(is_mismatch(holds(&Condition::all_in(set, lit("a")))));
    }

    #[test]
    fn ip_in_matches_ipv4_and_ipv6_blocks() {
        let v4 = |ip: &str, cidr: &str| holds(&Condition::ip_in(lit(ip), lit(cidr)));
        assert_eq!(v4("10.1.2.3", "10.0.0.0/8"), Ok(true));
        assert_eq!(v4("11.0.0.1", "10.0.0.0/8"), Ok(false));
        assert_eq!(v4("10.0.0.1", "10.0.0.1"), Ok(true), "no prefix is a single host");
        assert_eq!(v4("10.0.0.2", "10.0.0.1"), Ok(false));
        assert_eq!(v4("1.2.3.4", "0.0.0.0/0"), Ok(true));
        assert_eq!(v4("2001:db8::1", "2001:db8::/32"), Ok(true));
        assert_eq!(v4("2001:db9::1", "2001:db8::/32"), Ok(false));
        assert_eq!(v4("::1", "::1/128"), Ok(true));
        assert_eq!(v4("2001:db8::1", "::/0"), Ok(true));
        assert_eq!(v4("10.0.0.1", "2001:db8::/32"), Ok(false), "families do not mix");
    }

    #[test]
    fn ip_in_reads_an_ipv4_mapped_ipv6_address_as_ipv4() {
        let ip = |ip: &str, cidr: &str| holds(&Condition::ip_in(lit(ip), lit(cidr)));
        assert_eq!(ip("::ffff:10.1.2.3", "10.0.0.0/8"), Ok(true));
        assert_eq!(ip("::ffff:11.1.2.3", "10.0.0.0/8"), Ok(false));
        assert_eq!(ip("10.1.2.3", "::ffff:10.0.0.0/104"), Ok(true));
        assert_eq!(ip("10.1.2.3", "::ffff:11.0.0.0/104"), Ok(false));
        assert_eq!(ip("::ffff:10.1.2.3", "::ffff:10.0.0.0/104"), Ok(true));
    }

    #[test]
    fn ip_in_takes_a_list_of_blocks() {
        let blocks = lit(Value::from(vec!["10.0.0.0/8", "192.168.0.0/16"]));
        assert_eq!(holds(&Condition::ip_in(lit("192.168.1.1"), blocks.clone())), Ok(true));
        assert_eq!(holds(&Condition::ip_in(lit("172.16.0.1"), blocks)), Ok(false));
        assert_eq!(
            holds(&Condition::ip_in(lit("10.0.0.1"), lit(Value::List(vec![])))),
            Ok(false)
        );
    }

    #[test]
    fn ip_in_rejects_invalid_addresses_and_blocks() {
        for bad in [
            "10.0.0.0/33",
            "10.0.0.0/",
            "10.0.0.0/-1",
            "10.0.0/8",
            "nope",
            "",
            "::1/129",
            "10.0.0.0/8/8",
        ] {
            assert!(
                is_mismatch(holds(&Condition::ip_in(lit("10.0.0.1"), lit(bad)))),
                "{bad}"
            );
        }
        assert!(is_mismatch(holds(&Condition::ip_in(
            lit("10.0.0.256"),
            lit("10.0.0.0/8")
        ))));
        assert!(is_mismatch(holds(&Condition::ip_in(lit(5), lit("10.0.0.0/8")))));
        assert!(is_mismatch(holds(&Condition::ip_in(lit("10.0.0.1"), lit(5)))));
        assert!(is_mismatch(holds(&Condition::ip_in(
            lit("10.0.0.1"),
            lit(Value::List(vec![Value::Int(1)]))
        ))));
        // a bad block after a match is not reached, one before it fails
        let tail = lit(Value::from(vec!["10.0.0.0/8", "bad"]));
        assert_eq!(holds(&Condition::ip_in(lit("10.0.0.1"), tail)), Ok(true));
        let head = lit(Value::from(vec!["bad", "10.0.0.0/8"]));
        assert!(is_mismatch(holds(&Condition::ip_in(lit("10.0.0.1"), head))));
    }

    const MINUTE: u64 = 60_000;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    // 2024-01-01 was a Monday.
    const MONDAY: u64 = 1_704_067_200_000;

    #[test]
    fn time_between_is_half_open_in_utc() {
        let c = Condition::time_between("09:00", "17:30");
        assert_eq!(holds_at(&c, MONDAY + 8 * HOUR + 59 * MINUTE), Ok(false));
        assert_eq!(holds_at(&c, MONDAY + 9 * HOUR), Ok(true));
        assert_eq!(holds_at(&c, MONDAY + 17 * HOUR + 29 * MINUTE + 59_999), Ok(true));
        assert_eq!(holds_at(&c, MONDAY + 17 * HOUR + 30 * MINUTE), Ok(false));
        assert_eq!(holds_at(&c, 0), Ok(false), "the epoch is midnight UTC");
    }

    #[test]
    fn time_between_accepts_a_window_that_crosses_midnight() {
        let c = Condition::time_between("22:00", "06:00");
        assert_eq!(holds_at(&c, MONDAY + 21 * HOUR + 59 * MINUTE), Ok(false));
        assert_eq!(holds_at(&c, MONDAY + 22 * HOUR), Ok(true));
        assert_eq!(holds_at(&c, MONDAY + 23 * HOUR + 59 * MINUTE), Ok(true));
        assert_eq!(holds_at(&c, MONDAY), Ok(true), "midnight");
        assert_eq!(holds_at(&c, MONDAY + 5 * HOUR + 59 * MINUTE), Ok(true));
        assert_eq!(holds_at(&c, MONDAY + 6 * HOUR), Ok(false));
        assert_eq!(holds_at(&c, MONDAY + 12 * HOUR), Ok(false));
        let to_midnight = Condition::time_between("22:00", "00:00");
        assert_eq!(holds_at(&to_midnight, MONDAY + 23 * HOUR), Ok(true));
        assert_eq!(holds_at(&to_midnight, MONDAY), Ok(false));
    }

    #[test]
    fn time_between_with_equal_bounds_is_an_empty_window() {
        let c = Condition::time_between("09:00", "09:00");
        assert_eq!(holds_at(&c, MONDAY + 9 * HOUR), Ok(false));
        assert_eq!(holds_at(&c, MONDAY), Ok(false));
    }

    #[test]
    fn time_between_rejects_malformed_clock_times() {
        for bad in ["24:00", "9:00", "09:60", "09-00", "", "09:00:00", "ab:cd"] {
            let c = Condition::time_between(bad, "10:00");
            assert!(is_mismatch(holds_at(&c, MONDAY)), "{bad}");
        }
    }

    #[test]
    fn weekday_in_reads_the_utc_weekday() {
        let c = Condition::weekday_in(["mon", "sun"]);
        assert_eq!(holds_at(&c, MONDAY), Ok(true));
        assert_eq!(holds_at(&c, MONDAY + DAY - 1), Ok(true));
        assert_eq!(holds_at(&c, MONDAY + DAY), Ok(false), "tuesday");
        assert_eq!(holds_at(&c, MONDAY + 6 * DAY), Ok(true), "sunday");
        assert_eq!(holds_at(&c, 0), Ok(false), "the epoch was a thursday");
        assert_eq!(holds_at(&Condition::weekday_in(["thu"]), 0), Ok(true));
        assert_eq!(
            holds_at(&Condition::weekday_in(Vec::<String>::new()), MONDAY),
            Ok(false)
        );
        assert!(is_mismatch(holds_at(&Condition::weekday_in(["monday"]), MONDAY)));
    }

    #[test]
    fn time_conditions_without_an_instant_are_an_error_that_closes_access() {
        let missing = Err(ConditionError::MissingAttribute("now".to_string()));
        assert_eq!(holds(&Condition::time_between("00:00", "23:59")), missing);
        assert_eq!(holds(&Condition::weekday_in(["mon"])), missing);
        let nested = Condition::not(Condition::all([Condition::weekday_in(["mon"])]));
        assert_eq!(holds(&nested), missing);
        assert_eq!(
            holds_at(&nested, MONDAY),
            Ok(false),
            "the instant reaches nested conditions"
        );
    }

    #[test]
    fn new_conditions_have_their_own_json_shape() {
        let cases = [
            r#"{"op":"starts_with","left":{"attr":"resource.id"},"right":"draft"}"#,
            r#"{"op":"ends_with","left":"a.pdf","right":".pdf"}"#,
            r#"{"op":"contains","left":["a"],"right":"a"}"#,
            r#"{"op":"any_in","left":["a"],"right":["a","b"]}"#,
            r#"{"op":"all_in","left":["a"],"right":["a","b"]}"#,
            r#"{"op":"ip_in","item":{"attr":"env.ip"},"set":["10.0.0.0/8"]}"#,
            r#"{"op":"time_between","from":"22:00","until":"06:00"}"#,
            r#"{"op":"weekday_in","days":["mon","tue"]}"#,
        ];
        for json in cases {
            let cond: Condition = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&cond).unwrap(), json);
        }
    }

    #[cfg(feature = "tz")]
    mod zones {
        use super::*;

        const NEW_YORK: &str = "America/New_York";
        const SAO_PAULO: &str = "America/Sao_Paulo";
        // 2024-03-10 00:00 UTC; New York jumped from 02:00 EST to 03:00 EDT at 07:00 UTC.
        const SPRING_DAY: u64 = MONDAY + 69 * DAY;
        // 2024-11-03 00:00 UTC; New York fell back from 02:00 EDT to 01:00 EST at 06:00 UTC.
        const FALL_DAY: u64 = MONDAY + 307 * DAY;

        fn zoned(from: &str, until: &str, zone: &str) -> Condition {
            Condition::time_between(from, until).in_tz(zone)
        }

        fn minutes_holding(c: &Condition, from: u64, until: u64) -> Vec<u64> {
            (from..until)
                .step_by(MINUTE as usize)
                .filter(|at| holds_at(c, *at) == Ok(true))
                .collect()
        }

        #[test]
        fn sao_paulo_is_three_hours_behind_utc_all_year() {
            let c = zoned("09:00", "18:00", SAO_PAULO);
            assert_eq!(holds_at(&c, MONDAY + 11 * HOUR + 59 * MINUTE), Ok(false));
            assert_eq!(holds_at(&c, MONDAY + 12 * HOUR), Ok(true));
            assert_eq!(holds_at(&c, MONDAY + 20 * HOUR + 59 * MINUTE), Ok(true));
            assert_eq!(holds_at(&c, MONDAY + 21 * HOUR), Ok(false));
            let july = MONDAY + 182 * DAY;
            assert_eq!(
                holds_at(&c, july + 12 * HOUR),
                Ok(true),
                "no daylight saving time since 2019"
            );
            assert_eq!(holds_at(&c, july + 11 * HOUR + 59 * MINUTE), Ok(false));
        }

        #[test]
        fn the_weekday_follows_the_local_date() {
            let sunday_night = MONDAY + 2 * HOUR;
            assert_eq!(holds_at(&Condition::weekday_in(["mon"]), sunday_night), Ok(true));
            let local = Condition::weekday_in(["sun"]).in_tz(SAO_PAULO);
            assert_eq!(holds_at(&local, sunday_night), Ok(true), "23:00 on Sunday in Sao Paulo");
            assert_eq!(
                holds_at(&Condition::weekday_in(["mon"]).in_tz(SAO_PAULO), sunday_night),
                Ok(false)
            );
            let east = Condition::weekday_in(["tue"]).in_tz("Pacific/Auckland");
            assert_eq!(
                holds_at(&east, MONDAY + 12 * HOUR),
                Ok(true),
                "01:00 on Tuesday, UTC+13 in January"
            );
        }

        #[test]
        fn a_window_crossing_midnight_reads_the_local_clock() {
            let c = zoned("22:00", "06:00", SAO_PAULO);
            assert_eq!(holds_at(&c, MONDAY + HOUR), Ok(true), "22:00 local");
            assert_eq!(holds_at(&c, MONDAY + 8 * HOUR + 59 * MINUTE), Ok(true), "05:59 local");
            assert_eq!(holds_at(&c, MONDAY + 9 * HOUR), Ok(false), "06:00 local");
            assert_eq!(holds_at(&c, MONDAY + 12 * HOUR), Ok(false));
        }

        #[test]
        fn the_hour_skipped_by_spring_forward_never_holds() {
            let skipped = zoned("02:00", "03:00", NEW_YORK);
            assert!(minutes_holding(&skipped, SPRING_DAY, SPRING_DAY + DAY).is_empty());
            assert_eq!(
                minutes_holding(&skipped, SPRING_DAY - DAY, SPRING_DAY).len(),
                60,
                "the day before"
            );
        }

        #[test]
        fn a_window_over_the_spring_jump_loses_the_skipped_hour() {
            let c = zoned("01:00", "04:00", NEW_YORK);
            assert_eq!(
                holds_at(&c, SPRING_DAY + 5 * HOUR + 59 * MINUTE),
                Ok(false),
                "00:59 EST"
            );
            assert_eq!(holds_at(&c, SPRING_DAY + 6 * HOUR), Ok(true), "01:00 EST");
            assert_eq!(holds_at(&c, SPRING_DAY + 6 * HOUR + 59 * MINUTE), Ok(true), "01:59 EST");
            assert_eq!(
                holds_at(&c, SPRING_DAY + 7 * HOUR),
                Ok(true),
                "03:00 EDT, right after 01:59"
            );
            assert_eq!(holds_at(&c, SPRING_DAY + 7 * HOUR + 59 * MINUTE), Ok(true), "03:59 EDT");
            assert_eq!(holds_at(&c, SPRING_DAY + 8 * HOUR), Ok(false), "04:00 EDT");
            assert_eq!(
                minutes_holding(&c, SPRING_DAY, SPRING_DAY + DAY).len(),
                2 * 60,
                "two real hours"
            );
        }

        #[test]
        fn the_hour_repeated_by_fall_back_holds_both_times() {
            let c = zoned("01:00", "02:00", NEW_YORK);
            assert_eq!(holds_at(&c, FALL_DAY + 4 * HOUR + 59 * MINUTE), Ok(false), "00:59 EDT");
            assert_eq!(holds_at(&c, FALL_DAY + 5 * HOUR + 30 * MINUTE), Ok(true), "01:30 EDT");
            assert_eq!(holds_at(&c, FALL_DAY + 6 * HOUR + 30 * MINUTE), Ok(true), "01:30 EST");
            assert_eq!(holds_at(&c, FALL_DAY + 7 * HOUR), Ok(false), "02:00 EST");
            assert_eq!(
                minutes_holding(&c, FALL_DAY, FALL_DAY + DAY).len(),
                2 * 60,
                "both passes"
            );
        }

        #[test]
        fn the_offset_changes_the_utc_hour_of_a_fixed_local_window() {
            let c = zoned("09:00", "17:00", NEW_YORK);
            assert_eq!(holds_at(&c, SPRING_DAY - DAY + 14 * HOUR), Ok(true), "09:00 EST");
            assert_eq!(
                holds_at(&c, SPRING_DAY + 12 * HOUR + 59 * MINUTE),
                Ok(false),
                "08:59 EDT"
            );
            assert_eq!(holds_at(&c, SPRING_DAY + 13 * HOUR), Ok(true), "09:00 EDT");
        }

        #[test]
        fn an_unknown_zone_is_refused_up_front_and_fails_the_evaluation() {
            assert!(check_tz(SAO_PAULO).is_ok());
            assert!(check_tz("UTC").is_ok());
            for bad in ["Mars/Olympus", "", "sao paulo", "america/sao_paulo "] {
                assert!(check_tz(bad).unwrap_err().contains("IANA"), "{bad}");
            }
            let c = zoned("09:00", "17:00", "Mars/Olympus");
            assert!(matches!(holds_at(&c, MONDAY), Err(ConditionError::Function(_))));
        }

        #[test]
        fn in_tz_touches_only_the_two_time_conditions() {
            let other = Condition::exists("subject.id");
            assert_eq!(other.clone().in_tz(NEW_YORK), other);
            assert_eq!(
                Condition::time_between("09:00", "17:00").in_tz("UTC"),
                zoned("09:00", "17:00", "UTC")
            );
        }

        #[test]
        fn the_zone_is_optional_in_the_json_and_kept_when_given() {
            let plain: Condition =
                serde_json::from_str(r#"{"op":"time_between","from":"09:00","until":"17:00"}"#).unwrap();
            assert_eq!(plain, Condition::time_between("09:00", "17:00"));
            for json in [
                r#"{"op":"time_between","from":"09:00","until":"17:00","tz":"America/Sao_Paulo"}"#,
                r#"{"op":"weekday_in","days":["mon"],"tz":"Europe/Lisbon"}"#,
            ] {
                let cond: Condition = serde_json::from_str(json).unwrap();
                assert_eq!(serde_json::to_string(&cond).unwrap(), json);
            }
        }

        #[test]
        fn the_trace_label_names_the_local_time() {
            let at = MONDAY + 15 * HOUR + 30 * MINUTE;
            assert_eq!(
                clock_label(Some(at), Some(SAO_PAULO), false),
                "12:30 America/Sao_Paulo (UTC-03:00)"
            );
            assert_eq!(clock_label(Some(at), None, false), "15:30 UTC");
            assert_eq!(clock_label(Some(at), Some(SAO_PAULO), true), "America/Sao_Paulo (mon)");
            assert_eq!(clock_label(None, Some(SAO_PAULO), false), "America/Sao_Paulo");
            assert_eq!(clock_label(None, None, true), "UTC");
            assert_eq!(
                clock_label(Some(at), Some("Asia/Kolkata"), false),
                "21:00 Asia/Kolkata (UTC+05:30)"
            );
        }
    }
}
