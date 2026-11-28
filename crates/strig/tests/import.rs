//! Equivalence of the importers: every fixture is a model, a policy and a table of requests with
//! the answers the documentation of the source library gives. The table is decided on the
//! imported policy and compared. Casbin and OpenFGA are not run here.

use std::fs;
use std::path::{Path, PathBuf};

use strig::dsl::{Language, parse, print};
use strig::import::{casbin, openfga};
use strig::{Attributes, Context, InMemoryTuples, Request, Resource, Subject, Value};

fn fixtures(kind: &str) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/import")
        .join(kind);
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn read(dir: &Path, name: &str) -> String {
    fs::read_to_string(dir.join(name)).unwrap_or_default()
}

fn table(text: &str) -> Vec<std::collections::BTreeMap<String, String>> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header: Vec<String> = lines.next().unwrap().split(',').map(|s| s.trim().to_string()).collect();
    lines
        .map(|line| {
            header
                .iter()
                .cloned()
                .zip(line.split(',').map(|s| s.trim().to_string()))
                .collect()
        })
        .collect()
}

fn attrs(text: &str) -> Attributes {
    text.split(';')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap();
            let value = v.parse::<i64>().map_or_else(|_| Value::Str(v.to_string()), Value::Int);
            (k.to_string(), value)
        })
        .collect()
}

fn all_syntaxes_round_trip(policy: &strig::dsl::Policy, name: &str) {
    for language in [Language::Blocks, Language::Rules, Language::Actors] {
        let text = print(policy, language).unwrap_or_else(|e| panic!("{name}: print {language}: {e}"));
        let back = parse(name, &text).unwrap_or_else(|e| panic!("{name}: reparse {language}:\n{e}\n{text}"));
        assert!(
            back.policy.equivalent(policy),
            "{name}: {language} does not read back to the same policy"
        );
    }
    let json = policy.to_json().unwrap();
    assert!(
        strig::dsl::Policy::from_json(&json).unwrap().equivalent(policy),
        "{name}: JSON"
    );
}

#[test]
fn casbin_fixtures_decide_like_casbin() {
    let dirs = fixtures("casbin");
    assert!(dirs.len() >= 10);
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let actions: Vec<String> = read(&dir, "actions.txt").lines().map(str::to_string).collect();
        let options = casbin::Options {
            actions,
            ..casbin::Options::default()
        };
        let imported = casbin::import(&read(&dir, "model.conf"), &read(&dir, "policy.csv"), &options)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let policy = imported.policy();
        all_syntaxes_round_trip(policy, &name);
        let engine = policy.engine_spec().build().unwrap_or_else(|e| panic!("{name}: {e}"));
        let grants = policy.grants.clone();
        let ctx = Context::new(&grants);
        let rows = table(&read(&dir, "requests.csv"));
        assert!(!rows.is_empty(), "{name}: no requests");
        for row in rows {
            let mut subject: Subject = imported.subject(&row["sub"]);
            if let Some(a) = row.get("sub_attrs") {
                subject.attrs = attrs(a);
            }
            let expected = row["allowed"] == "true";
            let got = match imported.request(&row["obj"], &row["act"], row.get("dom").map(String::as_str)) {
                Some((permission, mut resource)) => {
                    if let Some(a) = row.get("obj_attrs") {
                        resource.attrs = attrs(a);
                    }
                    engine.check(&ctx, &Request::new(&subject, &permission, &resource))
                }
                None => false,
            };
            assert_eq!(got, expected, "{name}: {row:?}");
        }
    }
}

#[test]
fn openfga_fixtures_decide_like_openfga() {
    let dirs = fixtures("openfga");
    assert!(dirs.len() >= 7);
    for dir in dirs {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        let model = ["model.fga", "model.json"]
            .iter()
            .find_map(|f| fs::read_to_string(dir.join(f)).ok())
            .unwrap();
        let tuples = ["tuples.json", "tuples.txt", "tuples.csv", "tuples.yaml"]
            .iter()
            .find_map(|f| fs::read_to_string(dir.join(f)).ok())
            .unwrap_or_default();
        let imported =
            openfga::import(&model, &tuples, &openfga::Options::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let policy = imported.policy();
        all_syntaxes_round_trip(policy, &name);
        let engine = policy.engine_spec().build().unwrap_or_else(|e| panic!("{name}: {e}"));
        let grants = policy.grants.clone();
        let store: InMemoryTuples = policy.tuples.iter().cloned().collect();
        let ctx = Context::new(&grants).with_tuples(&store);
        for row in table(&read(&dir, "checks.csv")) {
            let (subject, permission, resource) = imported
                .request(&row["user"], &row["relation"], &row["object"])
                .unwrap_or_else(|| panic!("{name}: {row:?} names a relation the model lacks"));
            let got = engine.check(&ctx, &Request::new(&subject, &permission, &resource));
            assert_eq!(got, row["allowed"] == "true", "{name}: {row:?}");
        }
    }
}

const ACL: &str = "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n\
                   [policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\n";

fn casbin_with(matcher: &str) -> String {
    format!("{ACL}m = {matcher}\n")
}

fn refusal(model: &str, policy: &str) -> String {
    let err = casbin::import(model, policy, &casbin::Options::default()).expect_err("must be refused");
    err.to_string()
}

#[test]
fn casbin_matchers_without_a_faithful_translation_are_refused_with_position() {
    let said = refusal(
        &casbin_with("r.sub == p.sub && keyMatch2(r.obj, p.obj) && r.act == p.act"),
        "p, alice, /a/:id, read\n",
    );
    assert!(said.contains("model.conf:8:"), "{said}");
    assert!(said.contains("keyMatch2"), "{said}");

    let said = refusal(
        &casbin_with("r.sub == p.sub && globMatch(r.obj, p.obj) && r.act == p.act"),
        "",
    );
    assert!(said.contains("globMatch"), "{said}");

    let said = refusal(
        &casbin_with("!(r.sub == p.sub) && r.obj == p.obj && r.act == p.act"),
        "p, a, b, c\n",
    );
    assert!(said.contains("only `r.x == p.x`"), "{said}");

    let said = refusal(
        &casbin_with("r.sub != p.sub && r.obj == p.obj && r.act == p.act"),
        "p, a, b, c\n",
    );
    assert!(said.contains("only `r.x == p.x`"), "{said}");

    let said = refusal(
        &casbin_with("r.sub == p.sub && r.obj == p.obj && r.act == p.act && r.sub.Age + 1 > 3"),
        "p, a, b, c\n",
    );
    assert!(said.contains('+'), "{said}");
}

#[test]
fn casbin_regex_beyond_alternations_is_refused_at_the_policy_line() {
    let model = casbin_with("r.sub == p.sub && r.obj == p.obj && regexMatch(r.act, p.act)");
    let said = refusal(&model, "p, alice, data1, read\np, bob, data1, (read|wr.te)\n");
    assert!(said.contains("policy.csv:2:"), "{said}");
    assert!(said.contains("regular expression"), "{said}");
    let said = refusal(&model, "p, bob, data1, ^read\n");
    assert!(said.contains("anchor"), "{said}");
}

#[test]
fn casbin_second_definitions_and_unknown_effects_are_refused() {
    let said = refusal(
        "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n[role_definition]\ng = _, _\ng2 = _, _\n\
         [policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act\n",
        "",
    );
    assert!(said.contains("g2"), "{said}");
    assert!(said.contains("model.conf:7:"), "{said}");
    let said = refusal(
        "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n\
         [policy_effect]\ne = subjectPriority(p.eft) || deny\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n",
        "",
    );
    assert!(said.contains("subjectPriority"), "{said}");
}

#[test]
fn casbin_inheritance_scoped_to_a_domain_is_refused() {
    let model = "[request_definition]\nr = sub, dom, obj, act\n[policy_definition]\np = sub, dom, obj, act\n[role_definition]\ng = _, _, _\n\
                 [policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act\n";
    let said = refusal(
        model,
        "p, admin, d1, o, read\ng, alice, editor, d1\ng, editor, admin, d1\n",
    );
    assert!(said.contains("policy.csv:3:"), "{said}");
}

#[test]
fn casbin_model_without_actions_asks_for_them() {
    let said = refusal(&casbin_with("r.sub == r.obj.Owner"), "");
    assert!(said.contains("--action"), "{said}");
}

#[test]
fn casbin_notes_what_it_narrowed() {
    let model = casbin_with("r.sub == p.sub && r.obj == p.obj && r.act == p.act");
    let imported = casbin::import(
        &model,
        "p, alice, data1, read, deny\np, bob, data1, read, allow\n",
        &casbin::Options::default(),
    );
    assert!(imported.is_err(), "ACL without eft cannot hold a fourth field");
    let model = "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act, eft\n\
                 [policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n";
    let imported = casbin::import(
        model,
        "p, alice, data1, read, deny\np, bob, data1, read, allow\n",
        &casbin::Options::default(),
    )
    .unwrap();
    let report = imported.report();
    assert_eq!(report.notes.len(), 1, "{report}");
    assert!(report.notes[0].message.contains("deny dropped"));
    assert_eq!(imported.policy().grants.len(), 1);
    assert!(report.to_string().contains("converted:"));
}

#[test]
fn casbin_never_widens_a_wildcard_object() {
    let model = casbin_with("r.sub == p.sub && r.obj == p.obj && r.act == p.act");
    let imported = casbin::import(&model, "p, alice, *, read\n", &casbin::Options::default()).unwrap();
    let engine = imported.policy().engine_spec().build().unwrap();
    let grants = imported.policy().grants.clone();
    let ctx = Context::new(&grants);
    let alice = imported.subject("alice");
    let (permission, any) = imported.request("data1", "read", None).unwrap();
    assert!(!engine.check(&ctx, &Request::new(&alice, &permission, &any)));
    let (permission, star) = imported.request("*", "read", None).unwrap();
    assert!(engine.check(&ctx, &Request::new(&alice, &permission, &star)));
}

fn fga_refusal(model: &str, tuples: &str) -> String {
    openfga::import(model, tuples, &openfga::Options::default())
        .expect_err("must be refused")
        .to_string()
}

#[test]
fn openfga_conditions_are_refused_in_the_model_and_in_the_tuples() {
    let model = "model\n  schema 1.1\n\ntype user\n\ntype document\n  relations\n    define viewer: [user with in_office]\n\ncondition in_office(ip: string) {\n  ip == \"1\"\n}\n";
    let said = fga_refusal(model, "");
    assert!(said.contains("model.fga:8:"), "{said}");
    assert!(said.contains("CEL"), "{said}");
    assert!(said.contains("model.fga:10:"), "{said}");

    let plain = "model\n  schema 1.1\n\ntype user\n\ntype document\n  relations\n    define viewer: [user]\n";
    let said = fga_refusal(
        plain,
        r#"[{"user": "user:a", "relation": "viewer", "object": "document:1", "condition": {"name": "c"}}]"#,
    );
    assert!(said.contains("condition"), "{said}");

    let json = r#"{"schema_version":"1.1","type_definitions":[{"type":"user"},{"type":"document","relations":{"viewer":{"this":{}}},
        "metadata":{"relations":{"viewer":{"directly_related_user_types":[{"type":"user","condition":"c"}]}}}}],"conditions":{"c":{"name":"c","expression":"true"}}}"#;
    let said = fga_refusal(json, "");
    assert!(said.contains("condition `c`"), "{said}");
}

#[test]
fn openfga_mixed_operators_and_unknown_relations_are_refused() {
    let model = "model\n  schema 1.1\n\ntype user\n\ntype document\n  relations\n    define a: [user]\n    define b: [user]\n    define c: [user]\n    define x: a or b and c\n";
    let said = fga_refusal(model, "");
    assert!(said.contains("model.fga:11:"), "{said}");
    assert!(said.contains("parentheses"), "{said}");

    let plain = "model\n  schema 1.1\n\ntype user\n\ntype document\n  relations\n    define viewer: [user]\n";
    let said = fga_refusal(plain, "document:1#editor@user:a\n");
    assert!(said.contains("tuples:1:"), "{said}");
    assert!(said.contains("no relation `editor`"), "{said}");
}

#[test]
fn openfga_maps_each_rewrite_and_names_the_permissions() {
    let model = "model\n  schema 1.1\n\ntype user\n\ntype folder\n  relations\n    define viewer: [user]\n\ntype document\n  relations\n    define parent: [folder]\n    define viewer: [user] or viewer from parent\n    define blocked: [user]\n    define can_view: viewer but not blocked\n";
    let imported = openfga::import(model, "", &openfga::Options::default()).unwrap();
    let relations = imported.policy().relations.as_ref().unwrap();
    let find = |kind: &str, name: &str| relations.iter().find(|r| r.kind == kind && r.relation == name).unwrap();
    assert!(matches!(find("folder", "viewer").rewrite, strig::Rewrite::This));
    assert!(matches!(
        find("document", "viewer").rewrite,
        strig::Rewrite::Union { .. }
    ));
    assert!(matches!(
        find("document", "can_view").rewrite,
        strig::Rewrite::Exclusion { .. }
    ));
    assert_eq!(imported.permission("document", "can_view"), Some("document.can_view"));
    assert_eq!(imported.policy().grants.len(), 5);
    assert!(imported.request("anne", "viewer", "document:1").is_none());
    assert!(imported.request("user:anne", "nope", "document:1").is_none());
    assert!(!imported.report().converted.is_empty());
}

#[test]
fn imported_policy_fails_closed_for_what_the_source_never_said() {
    let model = "model\n  schema 1.1\n\ntype user\n\ntype document\n  relations\n    define viewer: [user]\n";
    let imported = openfga::import(model, "document:1#viewer@user:a\n", &openfga::Options::default()).unwrap();
    let engine = imported.policy().engine_spec().build().unwrap();
    let grants = imported.policy().grants.clone();
    let store: InMemoryTuples = imported.policy().tuples.iter().cloned().collect();
    let ctx = Context::new(&grants).with_tuples(&store);
    let a = Subject::of_kind("user", "a");
    let doc = Resource::new("document", "1");
    assert!(engine.check(&ctx, &Request::new(&a, "document.viewer", &doc)));
    assert!(!engine.check(&ctx, &Request::new(&a, "document.editor", &doc)));
    let ctx_without = Context::new(&grants);
    assert!(!engine.check(&ctx_without, &Request::new(&a, "document.viewer", &doc)));
}
