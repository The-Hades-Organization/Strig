//! The SQL text is checked without a database; the row-level behaviour needs a Postgres in
//! `THEMIS_PG_URL` and is skipped loudly without it.

use themis_postgres::{InstantOutOfRange, WindowColumns, candidate_predicate, window_predicate};

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
fn without_now_only_unwindowed_rows_and_possible_denies_pass() {
    let p = window_predicate(&WindowColumns::default(), 1, None).unwrap();
    assert_eq!(p.param, None);
    assert_eq!(
        p.sql,
        "((\"valid_from\" IS NULL AND \"valid_until\" IS NULL) OR \"effect\" IS DISTINCT FROM E'allow')"
    );
}

#[test]
fn column_names_are_quoted() {
    let columns = WindowColumns {
        valid_from: "a\"b".into(),
        valid_until: "until; DROP TABLE x".into(),
        effect: "effect".into(),
        allow_effect: "allow".into(),
    };
    let p = window_predicate(&columns, 1, Some(1)).unwrap();
    assert!(p.sql.contains("\"a\"\"b\""));
    assert!(p.sql.contains("\"until; DROP TABLE x\""));
}

#[test]
fn an_effect_that_is_not_known_to_be_allow_is_kept_without_now() {
    // `<> 'allow'` would drop NULL and keep nothing unknown safe; IS DISTINCT FROM keeps both.
    let p = window_predicate(&WindowColumns::default(), 1, None).unwrap();
    assert!(p.sql.contains("IS DISTINCT FROM"));
    assert!(!p.sql.contains("= 'deny'"), "a literal deny match drops other spellings of deny");
}

#[test]
fn the_allow_value_is_escaped() {
    let columns = WindowColumns {
        allow_effect: "a'b\\c".into(),
        ..WindowColumns::default()
    };
    let p = window_predicate(&columns, 1, None).unwrap();
    assert!(p.sql.contains(r"E'a''b\\c'"), "{}", p.sql);
}

#[test]
fn candidates_keep_future_starts_and_drop_only_what_expired() {
    let p = candidate_predicate(&WindowColumns::default(), 2, 1_000).unwrap();
    assert_eq!(p.param, Some(1_000));
    assert_eq!(p.sql, "(\"valid_until\" IS NULL OR \"valid_until\" > $2::bigint)");
    assert!(!p.sql.contains("valid_from"), "a later start must stay visible to the scheduler");
    assert_eq!(
        candidate_predicate(&WindowColumns::default(), 1, u64::MAX).unwrap_err(),
        InstantOutOfRange(u64::MAX)
    );
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
               ('deny_window', 'deny', 100, 200),
               ('deny_upper', 'DENY', 100, 200),
               ('deny_null', NULL, 100, 200),
               ('future', 'allow', 300, 400),
               ('expired', 'allow', 10, 50)",
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
    assert_eq!(
        ids(Some(100)).await,
        ["deny_null", "deny_upper", "deny_window", "open", "window"]
    );
    assert_eq!(
        ids(Some(199)).await,
        ["deny_null", "deny_upper", "deny_window", "open", "window"]
    );
    assert_eq!(ids(Some(200)).await, ["open"]);
    // No `now`: no windowed allow, but every windowed row that may be a deny stays.
    assert_eq!(ids(None).await, ["deny_null", "deny_upper", "deny_window", "open"]);

    let candidates = |now: u64| {
        let client = &client;
        async move {
            let p = candidate_predicate(&WindowColumns::default(), 1, now).unwrap();
            let sql = format!("SELECT id FROM grants_window WHERE {} ORDER BY id", p.sql);
            let bound = p.param.unwrap();
            let rows = client.query(&sql, &[&bound]).await.unwrap();
            rows.iter().map(|r| r.get::<_, String>(0)).collect::<Vec<_>>()
        }
    };
    // The grant that starts at 300 is a candidate while it is still in the future; the expired one is not.
    assert_eq!(
        candidates(150).await,
        ["deny_null", "deny_upper", "deny_window", "future", "open", "window"]
    );
    assert_eq!(candidates(400).await, ["open"]);
}
