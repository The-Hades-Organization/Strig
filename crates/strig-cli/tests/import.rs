//! `strig import` end to end, on files written for the case.

use std::fs;
use std::path::{Path, PathBuf};

use strig_cli::{EXIT_FAILED, EXIT_OK, EXIT_USAGE, execute};

const CASBIN_MODEL: &str = "[request_definition]\nr = sub, obj, act\n[policy_definition]\np = sub, obj, act\n\
[policy_effect]\ne = some(where (p.eft == allow))\n[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n";
const OPENFGA_MODEL: &str =
    "model\n  schema 1.1\n\ntype user\n\ntype document\n  relations\n    define viewer: [user]\n";

fn dir(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).unwrap();
    for (file, text) in files {
        fs::write(dir.join(file), text).unwrap();
    }
    dir
}

fn strig(args: &[&str]) -> (u8, String, String) {
    let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = execute(&args, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

fn path(dir: &Path, file: &str) -> String {
    dir.join(file).to_string_lossy().to_string()
}

#[test]
fn casbin_is_converted_in_every_syntax_and_reported() {
    let source = dir(
        "import-casbin",
        &[("model.conf", CASBIN_MODEL), ("policy.csv", "p, alice, data1, read\n")],
    );
    for language in ["blocks", "rules", "actors"] {
        let target = source.join(format!("out-{language}"));
        let (code, out, err) = strig(&[
            "import",
            "casbin",
            &path(&source, "model.conf"),
            &path(&source, "policy.csv"),
            "-o",
            target.to_str().unwrap(),
            "--language",
            language,
        ]);
        assert_eq!(code, EXIT_OK, "{language}: {err}{out}");
        assert!(out.contains("converted:"), "{out}");
        let text = fs::read_to_string(target.join("policy.strig")).unwrap();
        strig::dsl::parse("policy.strig", &text).unwrap_or_else(|e| panic!("{language}: {e}\n{text}"));
    }
}

#[test]
fn openfga_is_converted() {
    let source = dir(
        "import-openfga",
        &[
            ("model.fga", OPENFGA_MODEL),
            (
                "tuples.csv",
                "user_type,user_id,user_relation,relation,object_type,object_id\nuser,anne,,viewer,document,1\n",
            ),
        ],
    );
    let target = source.join("out");
    let (code, out, err) = strig(&[
        "import",
        "openfga",
        &path(&source, "model.fga"),
        &path(&source, "tuples.csv"),
        "-o",
        target.to_str().unwrap(),
    ]);
    assert_eq!(code, EXIT_OK, "{err}{out}");
    assert!(target.join("policy.strig").exists());
}

#[test]
fn what_has_no_translation_exits_one_with_the_position_and_writes_nothing() {
    let model = CASBIN_MODEL.replace("r.sub == p.sub", "keyMatch2(r.sub, p.sub)");
    let source = dir(
        "import-refused",
        &[("model.conf", &model), ("policy.csv", "p, alice, data1, read\n")],
    );
    let target = source.join("out");
    let (code, out, _) = strig(&[
        "import",
        "casbin",
        &path(&source, "model.conf"),
        &path(&source, "policy.csv"),
        "-o",
        target.to_str().unwrap(),
    ]);
    assert_eq!(code, EXIT_FAILED);
    assert!(out.contains("not converted:") && out.contains("keyMatch2"), "{out}");
    assert!(!target.join("policy.strig").exists());
}

#[test]
fn bad_usage_exits_two() {
    assert_eq!(strig(&["import"]).0, EXIT_USAGE);
    assert_eq!(strig(&["import", "casbin", "a", "b"]).0, EXIT_USAGE);
    assert_eq!(strig(&["import", "other", "a", "b", "-o", "x"]).0, EXIT_USAGE);
    assert_eq!(
        strig(&["import", "casbin", "missing.conf", "missing.csv", "-o", "x"]).0,
        EXIT_USAGE
    );
}
