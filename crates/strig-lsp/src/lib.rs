//! Language server for Strig policies.
//!
//! It speaks the Language Server Protocol over stdio and answers from the parser, validator,
//! formatter and converter of the `strig` crate, so the editor sees what `strig test` sees.
//!
//! A project is the directory of the open file: every `*.strig` in it joins one policy, as
//! `strig test <dir>` reads it, and every `*.strig-test.json` is a test file of that policy.
//! Unsaved buffers take the place of what is on disk.

mod analysis;
mod features;
mod text;

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, DidSaveTextDocument, Notification as _,
    PublishDiagnostics,
};
use lsp_types::request::{
    CodeActionRequest, Completion, Formatting, GotoDefinition, HoverRequest, Request as _, Shutdown,
};
use lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CompletionOptions, CompletionParams,
    CompletionResponse, DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, DocumentFormattingParams, GotoDefinitionParams, GotoDefinitionResponse, HoverParams,
    HoverProviderCapability, OneOf, PublishDiagnosticsParams, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, Uri,
};
use strig::dsl::MAX_SOURCE_BYTES;
use strig::dsl::fs::{EXTENSION, MAX_FILES, TEST_SUFFIX};

pub use analysis::{Analysis, Sources, analyze};

use crate::text::{path_of, uri_of};

type BoxError = Box<dyn Error + Send + Sync>;

/// Runs the server on stdin and stdout until the client exits.
///
/// # Errors
/// A protocol or IO failure; the client closing the connection after `shutdown` is not one.
pub fn serve_stdio() -> Result<(), BoxError> {
    let (connection, threads) = Connection::stdio();
    serve(&connection)?;
    drop(connection);
    threads.join()?;
    Ok(())
}

/// Runs the server on `connection`, for any transport (the tests use an in-memory one).
///
/// # Errors
/// A protocol failure.
pub fn serve(connection: &Connection) -> Result<(), BoxError> {
    let capabilities = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        completion_provider: Some(CompletionOptions {
            trigger_characters: Some(vec![".".into(), " ".into(), "\"".into(), "[".into()]),
            ..CompletionOptions::default()
        }),
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        definition_provider: Some(OneOf::Left(true)),
        document_formatting_provider: Some(OneOf::Left(true)),
        code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
        ..ServerCapabilities::default()
    };
    connection.initialize(serde_json::to_value(capabilities)?)?;
    let mut server = Server::default();
    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if request.method == Shutdown::METHOD {
                    connection
                        .sender
                        .send(Message::Response(Response::new_ok(request.id, ())))?;
                    // The `exit` notification follows; waiting for it is the spec's handshake.
                    for next in &connection.receiver {
                        if matches!(&next, Message::Notification(n) if n.method == "exit") {
                            break;
                        }
                    }
                    return Ok(());
                }
                let response = server.request(request);
                connection.sender.send(Message::Response(response))?;
            }
            Message::Notification(notification) => {
                for note in server.notification(notification) {
                    connection.sender.send(Message::Notification(note))?;
                }
            }
            Message::Response(_) => {}
        }
    }
    Ok(())
}

#[derive(Default)]
struct Server {
    /// The text of every open buffer.
    open: HashMap<PathBuf, String>,
    /// What was last read of each directory.
    analyzed: HashMap<PathBuf, (Sources, Analysis)>,
    /// The last policy of each directory that built, kept while the buffer is broken.
    last_good: HashMap<PathBuf, strig::dsl::Built>,
    /// Files that carry diagnostics at the client, so they can be cleared.
    published: HashSet<PathBuf>,
}

fn is_policy(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == EXTENSION)
}

fn is_test(path: &Path) -> bool {
    path.to_str().is_some_and(|p| p.ends_with(TEST_SUFFIX))
}

fn dir_of(path: &Path) -> Option<PathBuf> {
    path.parent().map(Path::to_path_buf)
}

fn read_regular(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > u64::try_from(MAX_SOURCE_BYTES).unwrap_or(u64::MAX) {
        return None;
    }
    fs::read_to_string(path).ok()
}

impl Server {
    fn gather(&self, dir: &Path) -> Sources {
        let mut names: Vec<PathBuf> = fs::read_dir(dir)
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        for path in self.open.keys() {
            if dir_of(path).as_deref() == Some(dir) && !names.contains(path) {
                names.push(path.clone());
            }
        }
        names.retain(|p| is_policy(p) || is_test(p));
        names.sort();
        names.truncate(MAX_FILES);
        let mut sources = Sources::default();
        for path in names {
            let Some(text) = self.open.get(&path).cloned().or_else(|| read_regular(&path)) else {
                continue;
            };
            let name = path.to_string_lossy().into_owned();
            if is_test(&path) {
                sources.tests.push((name, text));
            } else {
                sources.policies.push((name, text));
            }
        }
        sources
    }

    /// Reads `dir` again and returns the diagnostics to send.
    fn refresh(&mut self, dir: &Path) -> Vec<Notification> {
        let sources = self.gather(dir);
        let analysis = analyze(&sources);
        if let Some(built) = &analysis.built {
            self.last_good.insert(dir.to_path_buf(), built.clone());
        }
        let mut out = Vec::new();
        let mut now: HashSet<PathBuf> = HashSet::new();
        for (file, list) in &analysis.diagnostics {
            let path = PathBuf::from(file);
            let Some(uri) = uri_of(&path) else { continue };
            if !list.is_empty() {
                now.insert(path);
            }
            out.push(publish(uri, list.clone()));
        }
        let stale: Vec<PathBuf> = self
            .published
            .iter()
            .filter(|p| {
                dir_of(p).as_deref() == Some(dir)
                    && !now.contains(*p)
                    && !analysis.diagnostics.contains_key(&p.to_string_lossy().into_owned())
            })
            .cloned()
            .collect();
        for path in stale {
            if let Some(uri) = uri_of(&path) {
                out.push(publish(uri, Vec::new()));
            }
        }
        self.published.retain(|p| dir_of(p).as_deref() != Some(dir));
        self.published.extend(now);
        self.analyzed.insert(dir.to_path_buf(), (sources, analysis));
        out
    }

    fn notification(&mut self, note: Notification) -> Vec<Notification> {
        let dir_after = |server: &mut Server, uri: &Uri| -> Vec<Notification> {
            match path_of(uri)
                .filter(|p| is_policy(p) || is_test(p))
                .and_then(|p| dir_of(&p))
            {
                Some(dir) => server.refresh(&dir),
                None => Vec::new(),
            }
        };
        match note.method.as_str() {
            DidOpenTextDocument::METHOD => {
                let Ok(params) = serde_json::from_value::<DidOpenTextDocumentParams>(note.params) else {
                    return Vec::new();
                };
                if let Some(path) = path_of(&params.text_document.uri) {
                    self.open.insert(path, params.text_document.text);
                }
                dir_after(self, &params.text_document.uri)
            }
            DidChangeTextDocument::METHOD => {
                let Ok(params) = serde_json::from_value::<DidChangeTextDocumentParams>(note.params) else {
                    return Vec::new();
                };
                // Sync is FULL: the last change holds the whole text.
                if let (Some(path), Some(change)) = (
                    path_of(&params.text_document.uri),
                    params.content_changes.into_iter().last(),
                ) {
                    self.open.insert(path, change.text);
                }
                dir_after(self, &params.text_document.uri)
            }
            DidCloseTextDocument::METHOD => {
                let Ok(params) = serde_json::from_value::<DidCloseTextDocumentParams>(note.params) else {
                    return Vec::new();
                };
                if let Some(path) = path_of(&params.text_document.uri) {
                    self.open.remove(&path);
                }
                dir_after(self, &params.text_document.uri)
            }
            DidSaveTextDocument::METHOD => {
                let Ok(params) = serde_json::from_value::<DidSaveTextDocumentParams>(note.params) else {
                    return Vec::new();
                };
                dir_after(self, &params.text_document.uri)
            }
            _ => Vec::new(),
        }
    }

    /// The project of `path` as last read, reading it now when nothing was yet.
    fn project(&mut self, path: &Path) -> Option<(&Sources, Option<&strig::dsl::Built>)> {
        let dir = dir_of(path)?;
        if !self.analyzed.contains_key(&dir) {
            self.refresh(&dir);
        }
        let (sources, analysis) = self.analyzed.get(&dir)?;
        let built = analysis.built.as_ref().or_else(|| self.last_good.get(&dir));
        Some((sources, built))
    }

    fn request(&mut self, request: Request) -> Response {
        let Request { id, method, params } = request;
        let result = match method.as_str() {
            Completion::METHOD => self.completion(params),
            HoverRequest::METHOD => self.hover(params),
            GotoDefinition::METHOD => self.definition(params),
            Formatting::METHOD => self.formatting(params),
            CodeActionRequest::METHOD => self.code_actions(params),
            _ => return unknown(id, &method),
        };
        match result {
            Some(value) => Response::new_ok(id, value),
            None => Response::new_ok(id, serde_json::Value::Null),
        }
    }

    fn completion(&mut self, params: serde_json::Value) -> Option<serde_json::Value> {
        let params: CompletionParams = serde_json::from_value(params).ok()?;
        let at = params.text_document_position;
        let path = path_of(&at.text_document.uri)?;
        let text = self.text_of(&path)?;
        let (_, built) = self.project(&path)?;
        let items = features::complete(&text, at.position, built);
        serde_json::to_value(CompletionResponse::Array(items)).ok()
    }

    fn hover(&mut self, params: serde_json::Value) -> Option<serde_json::Value> {
        let params: HoverParams = serde_json::from_value(params).ok()?;
        let at = params.text_document_position_params;
        let path = path_of(&at.text_document.uri)?;
        let text = self.text_of(&path)?;
        let (_, built) = self.project(&path)?;
        serde_json::to_value(features::hover(&text, at.position, built)?).ok()
    }

    fn definition(&mut self, params: serde_json::Value) -> Option<serde_json::Value> {
        let params: GotoDefinitionParams = serde_json::from_value(params).ok()?;
        let at = params.text_document_position_params;
        let path = path_of(&at.text_document.uri)?;
        let text = self.text_of(&path)?;
        let (sources, built) = self.project(&path)?;
        let found = features::definition(&text, at.position, built, |file| {
            sources.text_of(file).map(str::to_string)
        })?;
        serde_json::to_value(GotoDefinitionResponse::Scalar(found)).ok()
    }

    fn formatting(&mut self, params: serde_json::Value) -> Option<serde_json::Value> {
        let params: DocumentFormattingParams = serde_json::from_value(params).ok()?;
        let path = path_of(&params.text_document.uri)?;
        if !is_policy(&path) {
            return None;
        }
        let text = self.text_of(&path)?;
        serde_json::to_value(features::format(&path.to_string_lossy(), &text)?).ok()
    }

    fn code_actions(&mut self, params: serde_json::Value) -> Option<serde_json::Value> {
        let params: CodeActionParams = serde_json::from_value(params).ok()?;
        let path = path_of(&params.text_document.uri)?;
        if !is_policy(&path) {
            return None;
        }
        let text = self.text_of(&path)?;
        let actions: Vec<CodeActionOrCommand> =
            features::conversions(&params.text_document.uri, &path.to_string_lossy(), &text)
                .into_iter()
                .map(CodeActionOrCommand::CodeAction)
                .collect();
        serde_json::to_value(actions).ok()
    }

    fn text_of(&self, path: &Path) -> Option<String> {
        self.open.get(path).cloned().or_else(|| read_regular(path))
    }
}

fn publish(uri: Uri, diagnostics: Vec<lsp_types::Diagnostic>) -> Notification {
    Notification::new(
        PublishDiagnostics::METHOD.to_string(),
        PublishDiagnosticsParams {
            uri,
            diagnostics,
            version: None,
        },
    )
}

fn unknown(id: RequestId, method: &str) -> Response {
    Response::new_err(
        id,
        lsp_server::ErrorCode::MethodNotFound as i32,
        format!("`{method}` is not supported"),
    )
}
