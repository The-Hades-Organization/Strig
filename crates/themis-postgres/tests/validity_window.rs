//! The SQL text is checked without a database; the row-level behaviour needs a Postgres in
//! `THEMIS_PG_URL` and is skipped loudly without it.

use themis_postgres::{InstantOutOfRange, WindowColumns, window_predicate};

#[test]
fn with_now_the_window_is_inclusive_from_and_exclusive_until() {
    let p = window_predicate(&WindowColumns::default(), 3, Some(1_000)).unwrap();
    assert_eq!(p.param, Some(1_000));
    assert_eq!(
        p.sql,
        "((\"valid_from\" IS NULL OR \"valid_from\" <= $3::bigint) AND (\"valid_until\" IS NULL OR \"valid_until\" > $3::bigint))"
    );
}

#[test]
fn without_now_only_unwindowed_rows_and_denies_pass() {
    let p = window_predicate(&WindowColumns::default(), 1, None).unwrap();
    assert_eq!(p.param, None);
    assert_eq!(
        p.sql,
        "((\"valid_from\" IS NULL AND \"valid_until\" IS NULL) OR \"effect\" = 'deny')"
    );
}

#[test]
fn column_names_are_quoted() {
    let columns = WindowColumns {
        valid_from: "a\"b".into(),
        valid_until: "until; DROP TABLE x".into(),
        effect: "effect".into(),
    };
    let p = window_predicate(&columns, 1, Some(1)).unwrap();
    assert!(p.sql.contains("\"a\"\"b\""));
    assert!(p.sql.contains("\"until; DROP TABLE x\""));
}

#[test]
fn an_instant_above_bigint_is_refused() {
    let error = window_predicate(&WindowColumns::default(), 1, Some(u64::MAX)).unwrap_err();
    assert_eq!(error, InstantOutOfRange(u64::MAX));
}

#[tokio::test]
async fn the_database_applies_the_window_at_the_edges() {
    let Ok(url) = std::env::var("THEMIS_PG_URL") else {
        eprintln!("THEMIS_PG_URL ausente: teste pulado");
        return;
    };
    let (client, conn) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(conn);
    client
        .batch_execute(
            "CREATE TEMP TABLE grants_window (id text, effect text, valid_from bigint, valid_until bigint);
             INSERT INTO grants_window VALUES
               ('open', 'allow', NULL, NULL),
               ('window', 'allow', 100, 200),
               ('deny_window', 'deny', 100, 200)",
        )
        .await
        .unwrap();

    let ids = |now: Option<u64>| {
        let client = &client;
        async move {
            let p = window_predicate(&WindowColumns::default(), 1, now).unwrap();
            let sql = format!("SELECT id FROM grants_window WHERE {} ORDER BY id", p.sql);
            let rows = match p.param {
                Some(bound) => client.query(&sql, &[&bound]).await.unwrap(),
                None => client.query(&sql, &[]).await.unwrap(),
            };
            rows.iter().map(|r| r.get::<_, String>(0)).collect::<Vec<_>>()
        }
    };

    assert_eq!(ids(Some(99)).await, ["open"]);
    assert_eq!(ids(Some(100)).await, ["deny_window", "open", "window"]);
    assert_eq!(ids(Some(199)).await, ["deny_window", "open", "window"]);
    assert_eq!(ids(Some(200)).await, ["open"]);
    assert_eq!(ids(None).await, ["deny_window", "open"]);
}
