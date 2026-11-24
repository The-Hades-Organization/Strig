//! The string, set, network and time conditions through the engine: decisions, listings, and the
//! rule that an error never opens access.

mod support;

use support::*;
use themis::{Attributes, Condition, Context, Decision, FilterResidual, Operand, QueryContext, Request, Subject, Value};

const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;
// 2024-01-01 00:00 UTC, a Monday.
const MONDAY: u64 = 1_704_067_200_000;

fn member() -> Subject {
    Subject::user("u1").with_role_in("member", org())
}

fn lit(v: impl Into<Value>) -> Operand {
    Operand::lit(v)
}

fn env(ip: &str) -> Attributes {
    Attributes::from([("ip".to_string(), Value::from(ip))])
}

fn allows(grants: &[themis::Grant], ctx: &Context<'_>, key: &str, doc: &themis::Resource) -> bool {
    let _ = grants;
    engine().check(ctx, &Request::new(&member(), key, doc))
}

fn decide(ctx: &Context<'_>, key: &str, doc: &themis::Resource) -> Decision {
    engine().decide(ctx, &Request::new(&member(), key, doc))
}

#[test]
fn an_allow_over_the_network_and_the_clock_holds_only_inside_both() {
    let office = Condition::all([
        Condition::ip_in(Operand::attr("env.ip"), lit(Value::from(vec!["10.0.0.0/8", "2001:db8::/32"]))),
        Condition::time_between("09:00", "17:00"),
        Condition::weekday_in(["mon", "tue", "wed", "thu", "fri"]),
    ]);
    let grants = vec![role_grant("g", "member", "document.edit", true, at_org()).when(office)];
    let doc = document("d1", "invoice");
    let at = |ip: &str, now: u64| {
        let env = env(ip);
        let ctx = Context::new(&grants).with_env(&env).at(now);
        allows(&grants, &ctx, "document.edit", &doc)
    };
    assert!(at("10.1.2.3", MONDAY + 9 * HOUR));
    assert!(at("::ffff:10.1.2.3", MONDAY + 16 * HOUR + 59 * MINUTE));
    assert!(at("2001:db8::7", MONDAY + 12 * HOUR));
    assert!(!at("10.1.2.3", MONDAY + 17 * HOUR), "the window is half open");
    assert!(!at("10.1.2.3", MONDAY + 8 * HOUR));
    assert!(!at("192.168.0.1", MONDAY + 12 * HOUR));
    assert!(!at("10.1.2.3", MONDAY + 5 * 24 * HOUR + 12 * HOUR), "saturday");
}

#[test]
fn an_allow_that_reads_the_clock_does_not_apply_without_an_instant() {
    let grants = vec![role_grant("g", "member", "document.edit", true, at_org()).when(Condition::time_between("00:00", "23:59"))];
    let doc = document("d1", "invoice");
    let ctx = Context::new(&grants);
    assert!(!allows(&grants, &ctx, "document.edit", &doc));
    assert!(allows(&grants, &ctx.at(MONDAY + HOUR), "document.edit", &doc));
}

#[test]
fn a_deny_that_cannot_be_evaluated_still_applies() {
    let grants = vec![
        role_grant("allow", "member", "document.edit", true, at_org()),
        role_grant("deny", "member", "document.edit", false, at_org()).when(Condition::weekday_in(["sat", "sun"])),
        role_grant("bad-deny", "member", "document.view", false, at_org())
            .when(Condition::ip_in(Operand::attr("env.ip"), lit("not a cidr"))),
        role_grant("view", "member", "document.view", true, at_org()),
    ];
    let doc = document("d1", "invoice");
    // no instant: the weekday cannot be read, the deny holds
    assert!(!allows(&grants, &Context::new(&grants), "document.edit", &doc));
    // a weekday: the deny does not apply
    assert!(allows(&grants, &Context::new(&grants).at(MONDAY), "document.edit", &doc));
    // saturday: it does
    assert!(!allows(&grants, &Context::new(&grants).at(MONDAY + 5 * 24 * HOUR), "document.edit", &doc));
    // an invalid CIDR is an error, and an error under a deny keeps the deny
    let env = env("10.0.0.1");
    assert!(!allows(&grants, &Context::new(&grants).with_env(&env).at(MONDAY), "document.view", &doc));
}

#[test]
fn a_text_condition_over_the_resource_decides_per_document() {
    let grants = vec![
        role_grant("g", "member", "document.edit", true, at_org())
            .when(Condition::starts_with(Operand::attr("resource.id"), lit("draft-"))),
    ];
    let ctx = Context::new(&grants);
    assert!(allows(&grants, &ctx, "document.edit", &document("draft-1", "invoice")));
    assert!(!allows(&grants, &ctx, "document.edit", &document("final-1", "invoice")));
    assert!(!decide(&ctx, "document.edit", &document("final-1", "invoice")).is_allowed());
}

#[test]
fn a_type_error_in_a_new_condition_never_opens_access() {
    let tags = Condition::any_in(Operand::attr("subject.tags"), lit(Value::from(vec!["a"])));
    let grants = vec![role_grant("g", "member", "document.edit", true, at_org()).when(tags)];
    let doc = document("d1", "invoice");
    let ctx = Context::new(&grants);
    // subject.tags is missing
    assert!(!allows(&grants, &ctx, "document.edit", &doc));
    // subject.tags is text, not a list
    let subject = member().with_attr("tags", "a");
    assert!(!engine().check(&ctx, &Request::new(&subject, "document.edit", &doc)));
    let subject = member().with_attr("tags", Value::from(vec!["a", "b"]));
    assert!(engine().check(&ctx, &Request::new(&subject, "document.edit", &doc)));
}

#[test]
fn listing_settles_a_time_condition_at_the_instant_of_the_query() {
    let grants = vec![role_grant("g", "member", "document.edit", true, at_org()).when(Condition::time_between("09:00", "17:00"))];
    let engine = engine();
    let doc = document("d1", "invoice");
    let listed = |now: Option<u64>| {
        let qctx = match now {
            Some(now) => QueryContext::new(&grants).at(now),
            None => QueryContext::new(&grants),
        };
        let filter = engine.list(&qctx, &member(), "document.edit", "document");
        (filter.resolve_with(&engine, &qctx.context(), std::slice::from_ref(&doc)), filter)
    };
    assert_eq!(listed(Some(MONDAY + 10 * HOUR)).0, vec!["d1".to_string()]);
    assert!(listed(Some(MONDAY + 20 * HOUR)).0.is_empty());
    let (none, filter) = listed(None);
    assert!(none.is_empty(), "without an instant the allow does not open anything");
    assert!(!filter.warnings().is_empty(), "and the listing says why");
}

#[test]
fn listing_leaves_a_new_condition_over_a_resource_attribute_as_a_residue() {
    let grants = vec![
        role_grant("g", "member", "document.edit", true, at_org())
            .when(Condition::ends_with(Operand::attr("resource.name"), lit(".md"))),
    ];
    let engine = engine();
    let qctx = QueryContext::new(&grants);
    let filter = engine.list(&qctx, &member(), "document.edit", "document");
    assert!(
        filter
            .residual()
            .iter()
            .any(|r| matches!(r, FilterResidual::Condition { grant_id, .. } if grant_id == "g"))
    );
    let md = document("d1", "invoice").with_attr("name", "a.md");
    let txt = document("d2", "invoice").with_attr("name", "a.txt");
    let bare = document("d3", "invoice");
    let ctx = qctx.context();
    let settled = filter.resolve_with(&engine, &ctx, &[md.clone(), txt.clone(), bare.clone()]);
    assert_eq!(settled, vec!["d1".to_string()]);
    for doc in [&md, &txt, &bare] {
        let expected = engine.check(&ctx, &Request::new(&member(), "document.edit", doc));
        assert_eq!(settled.iter().any(|id| doc.primary().and_then(|a| a.id.as_ref()) == Some(id)), expected);
    }
}
