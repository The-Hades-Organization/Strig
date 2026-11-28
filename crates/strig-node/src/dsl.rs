//! A linguagem de políticas no binding: a lógica comum aos dois alvos. Cada função devolve o JSON
//! canônico da política ou um `DslFailure` com `code` estável e os diagnósticos posicionados.

use std::collections::HashSet;

use serde_json::{Value, json};
use strig::dsl::{
    self, Diagnostic, Diagnostics, Language, Location, MAX_PROJECT_BYTES, MAX_SOURCE_BYTES, MAX_SOURCES, PrintError,
    Project,
};

use crate::BindingError;

/// Nome usado nas posições quando o texto não diz de qual arquivo veio.
const DEFAULT_FILE: &str = "<input>";

/// Quantos diagnósticos um erro leva: o núcleo corta em 100 e acrescenta uma linha "and N more";
/// o binding deixa passar essa linha e não mais que isso.
const MAX_DIAGNOSTICS: usize = 100;

/// Os códigos da linguagem, mais os do binding que ela reaproveita. `as_str` é o texto que chega
/// ao JavaScript e não muda entre versões.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DslCode {
    Parse,
    Validate,
    Conflict,
    Unrepresentable,
    Unsupported,
    /// Só o módulo nativo lê arquivos.
    #[cfg(feature = "dsl-fs")]
    Io,
    Limit,
    DuplicateSource,
    /// Um código do binding (`INVALID_ARGUMENT`, `INVALID_INPUT`, `INTERNAL`).
    Binding(&'static str),
}

impl DslCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "DSL_PARSE",
            Self::Validate => "DSL_VALIDATE",
            Self::Conflict => "DSL_CONFLICT",
            Self::Unrepresentable => "DSL_UNREPRESENTABLE",
            Self::Unsupported => "DSL_UNSUPPORTED",
            #[cfg(feature = "dsl-fs")]
            Self::Io => "DSL_IO",
            Self::Limit => "DSL_LIMIT",
            Self::DuplicateSource => "DSL_DUPLICATE_SOURCE",
            Self::Binding(code) => code,
        }
    }
}

/// Falha da linguagem: `code` estável (igual nos dois alvos), mensagem e diagnósticos.
#[derive(Debug, Clone, PartialEq)]
pub struct DslFailure {
    pub code: DslCode,
    pub message: String,
    pub diagnostics: Vec<Value>,
}

impl From<BindingError> for DslFailure {
    fn from(error: BindingError) -> Self {
        Self {
            code: DslCode::Binding(error.code),
            message: error.message,
            diagnostics: Vec::new(),
        }
    }
}

pub type DslResult<T> = Result<T, DslFailure>;

fn place(at: &Location) -> Value {
    json!({ "file": at.file.as_ref(), "line": at.line, "column": at.column })
}

fn diagnostic(found: &Diagnostic) -> Value {
    let (file, line, column) = match &found.location {
        Some(at) => (json!(at.file.as_ref()), json!(at.line), json!(at.column)),
        None => (Value::Null, Value::Null, Value::Null),
    };
    let mut out = json!({
        "file": file,
        "line": line,
        "column": column,
        "message": found.message,
        "hint": found.hint,
    });
    if let (Some(other), Some(map)) = (&found.related, out.as_object_mut()) {
        map.insert("related".to_string(), place(other));
    }
    out
}

fn failure(code: DslCode, found: &Diagnostics) -> DslFailure {
    DslFailure {
        code,
        message: found.to_string(),
        diagnostics: found.iter().take(MAX_DIAGNOSTICS + 1).map(diagnostic).collect(),
    }
}

/// Um conflito entre fontes aponta os dois lados; qualquer outra falha da montagem é validação.
fn project_code(found: &Diagnostics) -> DslCode {
    if found.iter().any(|d| d.related.is_some()) {
        DslCode::Conflict
    } else {
        DslCode::Validate
    }
}

fn unrepresentable(error: PrintError) -> DslFailure {
    let code = match error {
        PrintError::Unrepresentable { .. } => DslCode::Unrepresentable,
        _ => DslCode::Unsupported,
    };
    DslFailure {
        code,
        message: error.to_string(),
        diagnostics: Vec::new(),
    }
}

fn language(value: &Value) -> DslResult<Language> {
    let name = value
        .as_str()
        .ok_or_else(|| BindingError::invalid_argument("language", "esperado um texto"))?;
    name.parse().map_err(|()| {
        BindingError::invalid_argument("language", format!("`{name}` não é blocks, rules nem actors")).into()
    })
}

fn string<'a>(what: &str, value: &'a Value) -> DslResult<&'a str> {
    value
        .as_str()
        .ok_or_else(|| BindingError::invalid_argument(what, "esperado um texto").into())
}

fn to_value(policy: &dsl::Policy) -> DslResult<Value> {
    serde_json::to_value(policy).map_err(|e| BindingError::new("INTERNAL", e.to_string()).into())
}

/// Lê um texto em qualquer um dos três tipos. A falha é `DSL_PARSE` quando a sintaxe não fecha e
/// `DSL_VALIDATE` quando ela fecha e a política não vale.
fn read(file: &str, text: &str) -> DslResult<dsl::Parsed> {
    dsl::parse(file, text).map_err(|found| {
        let syntax = Project::new().add_source(file, text).is_err();
        failure(if syntax { DslCode::Parse } else { DslCode::Validate }, &found)
    })
}

/// `compile(text, { file? })`.
pub fn compile(text: &Value, options: Option<&Value>) -> DslResult<Value> {
    let text = string("text", text)?;
    let file = match options.and_then(|o| o.get("file")) {
        None | Some(Value::Null) => DEFAULT_FILE,
        Some(value) => string("file", value)?,
    };
    to_value(&read(file, text)?.policy)
}

/// `print(policy, language)`.
pub fn print(policy: &Value, to: &Value) -> DslResult<String> {
    let to = language(to)?;
    let policy: dsl::Policy =
        serde_json::from_value(policy.clone()).map_err(|e| BindingError::invalid_input("policy", e))?;
    policy.validate().map_err(|found| failure(DslCode::Validate, &found))?;
    dsl::print(&policy, to).map_err(unrepresentable)
}

/// `convert(text, language)`.
pub fn convert(text: &Value, to: &Value) -> DslResult<String> {
    let to = language(to)?;
    let parsed = read(DEFAULT_FILE, string("text", text)?)?;
    dsl::print(&parsed.policy, to).map_err(unrepresentable)
}

/// O nome do arquivo em `options.file`, ou o padrão.
#[cfg(any(feature = "napi", feature = "wasm"))]
fn file_option(options: Option<&Value>) -> DslResult<&str> {
    match options.and_then(|o| o.get("file")) {
        None | Some(Value::Null) => Ok(DEFAULT_FILE),
        Some(value) => string("file", value),
    }
}

/// `format(text, { file? })`: reescreve o texto no layout canônico da sintaxe que ele declara.
#[cfg(any(feature = "napi", feature = "wasm"))]
pub fn format(text: &Value, options: Option<&Value>) -> DslResult<String> {
    let parsed = read(file_option(options)?, string("text", text)?)?;
    dsl::print(&parsed.policy, parsed.language).map_err(unrepresentable)
}

/// `isFormatted(text, { file? })`: se o texto já está no layout canônico.
#[cfg(any(feature = "napi", feature = "wasm"))]
pub fn is_formatted(text: &Value, options: Option<&Value>) -> DslResult<bool> {
    let formatted = format(text, options)?;
    Ok(string("text", text)? == formatted)
}

/// Junta `[{ path, text }]` numa política só.
pub fn load_project(sources: &Value) -> DslResult<Value> {
    let list = sources
        .as_array()
        .ok_or_else(|| BindingError::invalid_argument("sources", "esperada uma lista de { path, text }"))?;
    let mut project = Project::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut bytes = 0usize;
    for item in list {
        let path = string("path", item.get("path").unwrap_or(&Value::Null))?;
        let text = string("text", item.get("text").unwrap_or(&Value::Null))?;
        // O núcleo recusa nome repetido e estouro de limite com um diagnóstico só; o binding
        // separa os dois casos da sintaxe antes de chamá-lo.
        if !seen.insert(path) {
            return Err(refusal(
                DslCode::DuplicateSource,
                path,
                format!("a fonte `{path}` já foi adicionada"),
            ));
        }
        bytes = bytes.saturating_add(text.len());
        if text.len() > MAX_SOURCE_BYTES || seen.len() > MAX_SOURCES || bytes > MAX_PROJECT_BYTES {
            return Err(refusal(
                DslCode::Limit,
                path,
                format!(
                    "limite do projeto: até {MAX_SOURCES} fontes, {MAX_SOURCE_BYTES} bytes cada e {MAX_PROJECT_BYTES} bytes no total"
                ),
            ));
        }
        project
            .add_source(path, text)
            .map_err(|found| failure(DslCode::Parse, &found))?;
    }
    build(&project)
}

fn refusal(code: DslCode, path: &str, message: String) -> DslFailure {
    let found = Diagnostic::new(Some(Location::new(path, 1, 1, 1)), message.clone());
    DslFailure {
        code,
        diagnostics: vec![diagnostic(&found)],
        message,
    }
}

fn build(project: &Project) -> DslResult<Value> {
    let built = project.build().map_err(|found| failure(project_code(&found), &found))?;
    // A montagem segue a ordem das fontes; o JSON canônico não depende dela.
    to_value(&built.policy.canonical())
}

/// `loadProjectDir(dir)`: só no módulo nativo, o wasm não tem IO.
#[cfg(feature = "dsl-fs")]
pub fn load_project_dir(dir: &Value) -> DslResult<Value> {
    use strig::dsl::fs::{FsError, read_dir};

    let project = read_dir(string("dir", dir)?).map_err(|error| {
        let code = match &error {
            FsError::Syntax(found) => return failure(DslCode::Parse, found),
            FsError::TooLarge { .. } | FsError::TooManyFiles { .. } => DslCode::Limit,
            _ => DslCode::Io,
        };
        DslFailure {
            code,
            message: error.to_string(),
            diagnostics: Vec::new(),
        }
    })?;
    build(&project)
}

/// `runTests(policy, tests)`: roda os arquivos de teste (`TestFile`, objetos ou o texto JSON de cada
/// um) contra a política, sem IO. Um `fixture` dado como caminho não é lido aqui: o caso vira erro.
pub fn run_tests(policy: &Value, tests: &Value) -> DslResult<Value> {
    use strig::dsl::testing::{self, TestFile};

    let policy = dsl::Policy::from_json(&policy.to_string()).map_err(|e| BindingError::invalid_input("policy", e))?;
    policy.validate().map_err(|found| failure(DslCode::Validate, &found))?;
    let list = tests
        .as_array()
        .ok_or_else(|| BindingError::invalid_argument("tests", "esperada uma lista de arquivos de teste"))?;
    let mut files = Vec::with_capacity(list.len());
    for (at, item) in list.iter().enumerate() {
        let text = match item {
            Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        let file =
            TestFile::parse(&format!("tests[{at}]"), &text).map_err(|e| BindingError::invalid_input("tests", e))?;
        files.push(file);
    }
    let report = testing::run(&policy, &files);
    serde_json::to_value(&report).map_err(|e| BindingError::new("INTERNAL", e.to_string()).into())
}

/// O resultado de uma chamada como o JavaScript o recebe: `{ ok: true, value }` ou
/// `{ ok: false, code, message, diagnostics }`. `dsl.js` o abre e lança o `Error`.
pub fn envelope<T: Into<Value>>(result: DslResult<T>) -> Value {
    match result {
        Ok(value) => json!({ "ok": true, "value": value.into() }),
        Err(e) => json!({ "ok": false, "code": e.code.as_str(), "message": e.message, "diagnostics": e.diagnostics }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKS: &str = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";

    fn code<T: std::fmt::Debug>(result: DslResult<T>) -> &'static str {
        result.expect_err("devia falhar").code.as_str()
    }

    #[test]
    fn compile_then_print_round_trips() {
        let policy = compile(&json!(BLOCKS), None).unwrap();
        assert_eq!(print(&policy, &json!("blocks")).unwrap(), BLOCKS);
    }

    #[test]
    fn syntax_error_is_parse_and_carries_position() {
        let e = compile(
            &json!("language blocks\n\npermission {"),
            Some(&json!({ "file": "a.strig" })),
        )
        .unwrap_err();
        assert_eq!(e.code, DslCode::Parse);
        assert_eq!(e.diagnostics[0]["file"], "a.strig");
        assert!(e.diagnostics[0]["line"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn invalid_policy_is_validate() {
        let text = "language blocks\n\npermission org.read {\n  targets = [org]\n}\n";
        assert_eq!(code(compile(&json!(text), None)), "DSL_VALIDATE");
    }

    #[test]
    fn clash_between_sources_is_conflict_with_both_sides() {
        let sources = json!([
            { "path": "a.strig", "text": BLOCKS },
            { "path": "b.strig", "text": BLOCKS },
        ]);
        let e = load_project(&sources).unwrap_err();
        assert_eq!(e.code, DslCode::Conflict);
        assert!(e.diagnostics.iter().any(|d| d["related"]["file"].is_string()));
    }

    #[test]
    fn bad_language_and_text_are_invalid_argument() {
        assert_eq!(code(convert(&json!(BLOCKS), &json!("yaml"))), "INVALID_ARGUMENT");
        assert_eq!(code(compile(&json!(1), None)), "INVALID_ARGUMENT");
    }

    #[test]
    fn run_tests_reports_each_case() {
        let policy = compile(&json!(BLOCKS), None).unwrap();
        let tests = json!([{"cases": [
            {"kind": "check", "name": "n", "subject": {"kind": "user", "id": "a"}, "permission": "org.read",
             "resource": "org:1", "expect": "deny", "reason": "no_applicable_grant"},
            {"kind": "check", "name": "wrong", "subject": {"kind": "user", "id": "a"}, "permission": "org.read",
             "resource": "org:1", "expect": "allow"}
        ]}]);
        let report = run_tests(&policy, &tests).unwrap();
        let outcomes: Vec<_> = report["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["outcome"].clone())
            .collect();
        assert_eq!(outcomes, [json!("passed"), json!("failed")]);
        assert_eq!(report["results"][0]["file"], "tests[0]");
    }

    #[test]
    fn run_tests_refuses_bad_input() {
        let policy = compile(&json!(BLOCKS), None).unwrap();
        assert_eq!(code(run_tests(&policy, &json!({"cases": []}))), "INVALID_ARGUMENT");
        assert_eq!(
            code(run_tests(&policy, &json!([{"cases": [], "extra": 1}]))),
            "INVALID_INPUT"
        );
        assert_eq!(code(run_tests(&json!({"nope": 1}), &json!([]))), "INVALID_INPUT");
    }

    #[test]
    fn envelope_shapes() {
        assert_eq!(envelope(Ok::<_, DslFailure>("x".to_string()))["ok"], true);
        let out = envelope(compile(&json!("nada"), None));
        assert_eq!(out["ok"], false);
        assert_eq!(out["code"], "DSL_PARSE");
    }
}
