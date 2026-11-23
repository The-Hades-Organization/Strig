//! Needs a Postgres in `THEMIS_PG_URL` (for example `postgres://postgres:pw@127.0.0.1:5432/postgres`).
//! Run with `THEMIS_PG_URL=... cargo test -p themis-postgres --test query -- --ignored`; without the
//! variable the test fails instead of passing without checking anything.

use std::collections::BTreeSet;

use themis::{
    Anchor, Catalog, Condition, Engine, Grant, InMemoryTuples, ObjectRef, Operand, PathLayout, PermissionDef,
    QueryContext, RelationSchema, Request, Resource, Rewrite, Subject, SubjectMatcher, TargetSelector, Tuple,
};
use themis_postgres::query::{PgTable, PgTables, filter_where};

fn catalog() -> Catalog {
    Catalog::builder()
        .target_kinds(["document", "project"])
        .broad_target("org")
        .permission(PermissionDef::new("document.view").targets(["project", "document"]))
        .permission(PermissionDef::new("document.edit").targets(["project", "document"]))
        .build()
        .unwrap()
}

fn grants() -> Vec<Grant> {
    let org = Anchor::new("org", "o1");
    vec![
        Grant::allow(
            "view",
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("org", "o1"),
        )
        .scoped(org),
        Grant::deny(
            "lock-p2",
            SubjectMatcher::role("member"),
            "document.view",
            TargetSelector::exact("project", "p2"),
        ),
        Grant::allow(
            "editors",
            SubjectMatcher::relation("editor"),
            "document.edit",
            TargetSelector::kind("project"),
        ),
        Grant::allow(
            "draft-edit",
            SubjectMatcher::role("member"),
            "document.edit",
            TargetSelector::exact("org", "o1"),
        )
        .when(Condition::eq(Operand::attr("resource.status"), Operand::lit("draft"))),
    ]
}

fn documents() -> Vec<Resource> {
    (0..12)
        .map(|n| {
            let mut doc = Resource::new("document", format!("d{n}"))
                .within("project", format!("p{}", n % 4))
                .within("org", if n < 10 { "o1" } else { "o2" });
            if n % 3 == 0 {
                doc = doc.with_attr("status", "draft");
            }
            doc
        })
        .collect()
}

#[tokio::test]
#[ignore = "needs THEMIS_PG_URL"]
async fn listing_translated_to_sql_matches_check_row_by_row() {
    let url = std::env::var("THEMIS_PG_URL").expect("THEMIS_PG_URL must point at a Postgres");
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    let connection = tokio::spawn(connection);

    let suffix = std::process::id();
    let tables = PgTables::new(format!("themis_grants_{suffix}"), format!("themis_tuples_{suffix}")).unwrap();
    let docs_table = format!("themis_docs_{suffix}");
    client.batch_execute(&tables.schema_sql()).await.unwrap();
    client
        .batch_execute(&format!(
            "CREATE TABLE {docs_table} (id text PRIMARY KEY, project_id text NOT NULL, org_id text NOT NULL, \
             status text)"
        ))
        .await
        .unwrap();

    let docs = documents();
    for doc in &docs {
        let id = doc.primary().and_then(|a| a.id.clone()).unwrap();
        let project = doc
            .locate(&TargetSelector::kind("project"))
            .and_then(|(_, a)| a.id.clone())
            .unwrap();
        let org = doc
            .locate(&TargetSelector::kind("org"))
            .and_then(|(_, a)| a.id.clone())
            .unwrap();
        let status = doc.attrs.get("status").map(|_| "draft".to_string());
        client
            .execute(
                &format!("INSERT INTO {docs_table} (id, project_id, org_id, status) VALUES ($1, $2, $3, $4)"),
                &[&id, &project, &org, &status],
            )
            .await
            .unwrap();
    }
    for grant in grants() {
        tables.put_grant(&client, &grant).await.unwrap();
    }
    let tuple = Tuple::new(
        ObjectRef::new("project", "p2"),
        "editor",
        ObjectRef::new("user", "erin"),
    );
    tables.put_tuple(&client, &tuple).await.unwrap();
    tables.put_tuple(&client, &tuple).await.unwrap();

    let by_permission = tables.grants_by_permission(&client, &["document.view"]).await.unwrap();
    assert_eq!(by_permission.len(), 2);
    assert_eq!(tables.grants_by_target_kind(&client, "project").await.unwrap().len(), 2);
    assert_eq!(
        tables
            .grants_by_subject(&client, &SubjectMatcher::role("member"))
            .await
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        tables.tuples_of_kind(&client, "project").await.unwrap(),
        vec![tuple.clone()]
    );
    assert_eq!(
        tables
            .tuples_of_object(&client, &ObjectRef::new("project", "p2"))
            .await
            .unwrap(),
        vec![tuple]
    );

    let loaded = tables
        .grants_by_permission(&client, &["document.view", "document.edit"])
        .await
        .unwrap();
    let store: InMemoryTuples = tables
        .tuples_of_kind(&client, "project")
        .await
        .unwrap()
        .into_iter()
        .collect();
    let engine = Engine::builder(catalog())
        .relations(RelationSchema::new().relation("project", "editor", Rewrite::This))
        .build()
        .unwrap();
    let qctx = QueryContext::new(&loaded).with_tuples(&store);
    let ctx = qctx.context();
    let layout = PathLayout::new("document").within("project").within("org");
    let table = PgTable::new("document", "id")
        .unwrap()
        .path_column("project", "project_id")
        .unwrap()
        .path_column("org", "org_id")
        .unwrap();

    let subjects = [
        Subject::user("u1").with_role_in("member", Anchor::new("org", "o1")),
        Subject::user("erin"),
        Subject::user("nobody"),
    ];
    for subject in subjects {
        for key in ["document.view", "document.edit"] {
            let expected: BTreeSet<String> = docs
                .iter()
                .filter(|doc| engine.check(&ctx, &Request::new(&subject, key, doc)))
                .filter_map(|doc| doc.primary().and_then(|a| a.id.clone()))
                .collect();
            let filter = engine.list(&qctx, &subject, key, "document");
            let translated = filter_where(&filter, &layout, &table, 1).unwrap();
            let sql = format!("SELECT id FROM {docs_table} WHERE {} ORDER BY id", translated.where_sql);
            let rows = client.query(&sql, &translated.sql_params()).await.unwrap();
            let candidates: BTreeSet<String> = rows.iter().map(|row| row.get(0)).collect();
            let settled: BTreeSet<String> = match &translated.settled_sql {
                Some(settled_sql) => {
                    let sql = format!("SELECT id FROM {docs_table} WHERE {settled_sql} ORDER BY id");
                    client
                        .query(&sql, &translated.sql_params())
                        .await
                        .unwrap()
                        .iter()
                        .map(|row| row.get(0))
                        .collect()
                }
                None => candidates.clone(),
            };
            assert!(
                settled.is_subset(&expected),
                "{:?} {key}: settled rows must be allowed",
                subject.id
            );
            let allowed: BTreeSet<String> = candidates
                .iter()
                .filter(|id| {
                    settled.contains(*id)
                        || docs
                            .iter()
                            .find(|d| d.primary().and_then(|a| a.id.as_deref()) == Some(id.as_str()))
                            .is_some_and(|d| engine.check(&ctx, &Request::new(&subject, key, d)))
                })
                .cloned()
                .collect();
            assert_eq!(allowed, expected, "{:?} {key}", subject.id);
        }
    }

    client
        .batch_execute(&format!(
            "DROP TABLE {docs_table}; DROP TABLE themis_grants_{suffix}; DROP TABLE themis_tuples_{suffix}"
        ))
        .await
        .unwrap();
    drop(client);
    connection.await.unwrap().unwrap();
}
