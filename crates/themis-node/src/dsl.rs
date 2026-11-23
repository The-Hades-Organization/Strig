//! A linguagem de políticas no binding: a lógica comum aos dois alvos. Cada função devolve o JSON
//! canônico da política ou um `DslFailure` com `code` estável e os diagnósticos posicionados.

use serde_json::{Value, json};
use themis::dsl::{self, Diagnostic, Diagnostics, Language, Location, PrintError, Project};

use crate::BindingError;

/// Nome usado nas posições quando o texto não diz de qual arquivo veio.
const DEFAULT_FILE: &str = "<input>";

/// Quantos diagnósticos um erro leva: o núcleo já corta em 100 na leitura; o que vem da validação
/// de uma política em JSON passa pelo mesmo teto.
const MAX_DIAGNOSTICS: usize = 100;

/// Falha da linguagem: `code` estável (igual nos dois alvos), mensagem e diagnósticos.
#[derive(Debug, Clone, PartialEq)]
pub struct DslFailure {
    pub code: &'static str,
    pub message: String,
    pub diagnostics: Vec<Value>,
}

impl From<BindingError> for DslFailure {
    fn from(error: BindingError) -> Self {
        Self {
            code: error.code,
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

fn failure(code: &'static str, found: &Diagnostics) -> DslFailure {
    DslFailure {
        code,
        message: found.to_string(),
        diagnostics: found.iter().take(MAX_DIAGNOSTICS).map(diagnostic).collect(),
    }
}

/// Um conflito entre fontes aponta os dois lados; qualquer outra falha da montagem é validação.
fn project_code(found: &Diagnostics) -> &'static str {
    if found.iter().any(|d| d.related.is_some()) {
        "DSL_CONFLICT"
    } else {
        "DSL_VALIDATE"
    }
}

fn unrepresentable(error: PrintError) -> DslFailure {
    let code = match error {
        PrintError::Unrepresentable { .. } => "DSL_UNREPRESENTABLE",
        _ => "DSL_UNSUPPORTED",
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
        failure(if syntax { "DSL_PARSE" } else { "DSL_VALIDATE" }, &found)
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
    policy.validate().map_err(|found| failure("DSL_VALIDATE", &found))?;
    dsl::print(&policy, to).map_err(unrepresentable)
}

/// `convert(text, language)`.
pub fn convert(text: &Value, to: &Value) -> DslResult<String> {
    let to = language(to)?;
    let parsed = read(DEFAULT_FILE, string("text", text)?)?;
    dsl::print(&parsed.policy, to).map_err(unrepresentable)
}

/// Junta `[{ path, text }]` numa política só.
pub fn load_project(sources: &Value) -> DslResult<Value> {
    let list = sources
        .as_array()
        .ok_or_else(|| BindingError::invalid_argument("sources", "esperada uma lista de { path, text }"))?;
    let mut project = Project::new();
    for item in list {
        let path = string("path", item.get("path").unwrap_or(&Value::Null))?;
        let text = string("text", item.get("text").unwrap_or(&Value::Null))?;
        project
            .add_source(path, text)
            .map_err(|found| failure("DSL_PARSE", &found))?;
    }
    build(&project)
}

fn build(project: &Project) -> DslResult<Value> {
    let built = project.build().map_err(|found| failure(project_code(&found), &found))?;
    // A montagem segue a ordem das fontes; o JSON canônico não depende dela.
    to_value(&built.policy.canonical())
}

/// `loadProjectDir(dir)`: só no módulo nativo, o wasm não tem IO.
#[cfg(feature = "dsl-fs")]
pub fn load_project_dir(dir: &Value) -> DslResult<Value> {
    use themis::dsl::fs::{FsError, read_dir};

    let project = read_dir(string("dir", dir)?).map_err(|error| match error {
        FsError::Syntax(found) => failure("DSL_PARSE", &found),
        other => DslFailure {
            code: "DSL_IO",
            message: other.to_string(),
            diagnostics: Vec::new(),
        },
    })?;
    build(&project)
}

/// O resultado de uma chamada como o JavaScript o recebe: `{ ok: true, value }` ou
/// `{ ok: false, code, message, diagnostics }`. `dsl.js` o abre e lança o `Error`.
pub fn envelope<T: Into<Value>>(result: DslResult<T>) -> Value {
    match result {
        Ok(value) => json!({ "ok": true, "value": value.into() }),
        Err(e) => json!({ "ok": false, "code": e.code, "message": e.message, "diagnostics": e.diagnostics }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKS: &str = "language blocks\n\ntarget_kinds = [org]\n\npermission org.read {\n  targets = [org]\n}\n";

    fn code<T: std::fmt::Debug>(result: DslResult<T>) -> &'static str {
        result.expect_err("devia falhar").code
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
            Some(&json!({ "file": "a.themis" })),
        )
        .unwrap_err();
        assert_eq!(e.code, "DSL_PARSE");
        assert_eq!(e.diagnostics[0]["file"], "a.themis");
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
            { "path": "a.themis", "text": BLOCKS },
            { "path": "b.themis", "text": BLOCKS },
        ]);
        let e = load_project(&sources).unwrap_err();
        assert_eq!(e.code, "DSL_CONFLICT");
        assert!(e.diagnostics.iter().any(|d| d["related"]["file"].is_string()));
    }

    #[test]
    fn bad_language_and_text_are_invalid_argument() {
        assert_eq!(code(convert(&json!(BLOCKS), &json!("yaml"))), "INVALID_ARGUMENT");
        assert_eq!(code(compile(&json!(1), None)), "INVALID_ARGUMENT");
    }

    #[test]
    fn envelope_shapes() {
        assert_eq!(envelope(Ok::<_, DslFailure>("x".to_string()))["ok"], true);
        let out = envelope(compile(&json!("nada"), None));
        assert_eq!(out["ok"], false);
        assert_eq!(out["code"], "DSL_PARSE");
    }
}
