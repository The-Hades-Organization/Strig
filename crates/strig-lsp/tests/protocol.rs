//! The server over real LSP messages, on an in-memory connection.

use std::fs;
use std::path::Path;
use std::thread;
use std::time::Duration;

use lsp_server::{Connection, Message, Notification, Request, RequestId};
use serde_json::{Value, json};

struct Client {
    connection: Connection,
    next: i32,
    server: Option<thread::JoinHandle<()>>,
}

fn uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

impl Client {
    fn start() -> Self {
        let (client, server) = Connection::memory();
        let handle = thread::spawn(move || {
            strig_lsp::serve(&server).expect("server runs");
        });
        let mut me = Self {
            connection: client,
            next: 1,
            server: Some(handle),
        };
        let init = me.request("initialize", json!({"capabilities": {}}));
        assert!(init["capabilities"]["hoverProvider"].as_bool().unwrap());
        me.notify("initialized", json!({}));
        me
    }

    fn notify(&self, method: &str, params: Value) {
        let note = Notification::new(method.to_string(), params);
        self.connection.sender.send(Message::Notification(note)).unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let request = Request::new(RequestId::from(id), method.to_string(), params);
        self.connection.sender.send(Message::Request(request)).unwrap();
        loop {
            match self
                .connection
                .receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("a reply")
            {
                Message::Response(response) if response.id == RequestId::from(id) => {
                    return response.response_result.expect("an answer, not an error");
                }
                _ => {}
            }
        }
    }

    /// The next `publishDiagnostics` for `file`.
    fn diagnostics_of(&self, file: &Path) -> Vec<Value> {
        let want = uri(file);
        loop {
            match self
                .connection
                .receiver
                .recv_timeout(Duration::from_secs(10))
                .expect("diagnostics")
            {
                Message::Notification(note)
                    if note.method == "textDocument/publishDiagnostics" && note.params["uri"] == want.as_str() =>
                {
                    return note.params["diagnostics"].as_array().unwrap().clone();
                }
                _ => {}
            }
        }
    }

    fn open(&self, file: &Path, text: &str) {
        self.notify(
            "textDocument/didOpen",
            json!({"textDocument": {"uri": uri(file), "languageId": "strig", "version": 1, "text": text}}),
        );
    }

    fn change(&self, file: &Path, text: &str, version: i32) {
        self.notify(
            "textDocument/didChange",
            json!({"textDocument": {"uri": uri(file), "version": version}, "contentChanges": [{"text": text}]}),
        );
    }

    fn finish(mut self) {
        self.request("shutdown", Value::Null);
        self.notify("exit", Value::Null);
        self.server.take().unwrap().join().unwrap();
    }
}

fn project() -> tempdir::Dir {
    let dir = tempdir::Dir::new();
    fs::write(
        dir.path().join("kinds.strig"),
        "language blocks\n\ntarget_kinds = [org]\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("read.strig"),
        "language blocks\n\npermission org.read {\n  label = \"Read\"\n  targets = [org]\n}\n",
    )
    .unwrap();
    dir
}

mod tempdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "strig-lsp-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }
}

#[test]
fn diagnostics_follow_the_buffer_and_clear_when_fixed() {
    let dir = project();
    let file = dir.path().join("read.strig");
    let client = Client::start();
    client.open(&file, &fs::read_to_string(&file).unwrap());
    assert!(client.diagnostics_of(&file).is_empty());

    client.change(
        &file,
        "language blocks\n\npermission org.read {\n  targets = [nowhere]\n}\n",
        2,
    );
    let found = client.diagnostics_of(&file);
    assert!(!found.is_empty(), "a kind that was never declared");
    assert_eq!(found[0]["severity"], 1);

    client.change(&file, &fs::read_to_string(&file).unwrap(), 3);
    assert!(client.diagnostics_of(&file).is_empty());
    client.finish();
}

#[test]
fn completion_offers_the_permissions_of_the_project() {
    let dir = project();
    let mut client = Client::start();
    let text = "language blocks\n\npermission org.edit {\n  targets = [org]\n  depends_on = [org.";
    fs::write(
        dir.path().join("edit.strig"),
        "language blocks\n\npermission org.edit {\n  targets = [org]\n}\n",
    )
    .unwrap();
    let edit = dir.path().join("edit.strig");
    client.open(&edit, text);
    let _ = client.diagnostics_of(&edit);
    let reply = client.request(
        "textDocument/completion",
        json!({"textDocument": {"uri": uri(&edit)}, "position": {"line": 4, "character": 21}}),
    );
    let labels: Vec<&str> = reply
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["label"].as_str().unwrap())
        .collect();
    assert!(labels.contains(&"org.read"), "{labels:?}");
    client.finish();
}

#[test]
fn hover_and_definition_cross_files() {
    let dir = project();
    let edit = dir.path().join("edit.strig");
    let text = "language blocks\n\npermission org.edit {\n  targets = [org]\n  depends_on = [org.read]\n}\n";
    fs::write(&edit, text).unwrap();
    let mut client = Client::start();
    client.open(&edit, text);
    assert!(client.diagnostics_of(&edit).is_empty());

    let position = json!({"line": 4, "character": 18});
    let hover = client.request(
        "textDocument/hover",
        json!({"textDocument": {"uri": uri(&edit)}, "position": position}),
    );
    let value = hover["contents"]["value"].as_str().unwrap();
    assert!(value.contains("**org.read** — Read"), "{value}");

    let found = client.request(
        "textDocument/definition",
        json!({"textDocument": {"uri": uri(&edit)}, "position": position}),
    );
    assert_eq!(found["uri"], uri(&dir.path().join("read.strig")).as_str());
    assert_eq!(found["range"]["start"]["line"], 2);
    client.finish();
}

#[test]
fn formatting_and_conversion_replace_the_document() {
    let dir = project();
    let file = dir.path().join("kinds.strig");
    let mut client = Client::start();
    let messy = "language blocks\ntarget_kinds=[org]\n";
    client.open(&file, messy);
    let _ = client.diagnostics_of(&file);

    let edits = client.request(
        "textDocument/formatting",
        json!({"textDocument": {"uri": uri(&file)}, "options": {"tabSize": 2, "insertSpaces": true}}),
    );
    assert_eq!(edits[0]["newText"], "language blocks\n\ntarget_kinds = [org]\n");

    let actions = client.request(
        "textDocument/codeAction",
        json!({"textDocument": {"uri": uri(&file)}, "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 0}}, "context": {"diagnostics": []}}),
    );
    let titles: Vec<&str> = actions
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Convert to rules syntax", "Convert to actors syntax"]);
    let rules = actions[0]["edit"]["changes"][uri(&file)][0]["newText"]
        .as_str()
        .unwrap();
    assert!(rules.starts_with("language rules"), "{rules}");
    client.finish();
}

#[test]
fn a_broken_test_file_is_diagnosed() {
    let dir = project();
    let tests = dir.path().join("a.strig-test.json");
    let client = Client::start();
    client.open(&tests, "{\n  \"cases\": [,]\n}");
    let found = client.diagnostics_of(&tests);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["range"]["start"]["line"], 1);
    client.finish();
}
