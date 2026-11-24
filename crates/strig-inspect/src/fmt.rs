//! `strig-inspect fmt`: reescreve arquivos `.strig` no layout canônico, ou só diz quais mudariam.

use std::fs;
use std::path::{Path, PathBuf};

use strig::dsl::{fs as policy_fs, print};

/// O que o comando encontrou, na ordem em que olhou os arquivos.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Os arquivos fora do layout canônico: reescritos, ou só listados com `--check`.
    pub changed: Vec<PathBuf>,
    /// Quantos já estavam formatados.
    pub unchanged: usize,
    /// Um erro por arquivo que não pôde ser lido ou compilado; o texto começa por `arquivo:linha:coluna`
    /// quando o erro tem posição.
    pub errors: Vec<String>,
}

impl Report {
    /// Se tudo estava formatado e nada falhou.
    pub fn is_clean(&self) -> bool {
        self.changed.is_empty() && self.errors.is_empty()
    }
}

fn files_of(path: &Path) -> Result<Vec<PathBuf>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
        let file = entry.path();
        if file.extension().is_some_and(|e| e == policy_fs::EXTENSION) {
            files.push(file);
        }
    }
    files.sort();
    if files.len() > policy_fs::MAX_FILES {
        return Err(format!(
            "{}: mais de {} arquivos .strig",
            path.display(),
            policy_fs::MAX_FILES
        ));
    }
    Ok(files)
}

fn one(file: &Path, check: bool) -> Result<bool, String> {
    let parsed = policy_fs::read_file(file).map_err(|e| e.to_string())?;
    let formatted = print(&parsed.policy, parsed.language).map_err(|e| format!("{}: {e}", file.display()))?;
    let current = fs::read_to_string(file).map_err(|e| format!("{}: {e}", file.display()))?;
    if current == formatted {
        return Ok(false);
    }
    if !check {
        policy_fs::write_file(file, &parsed.policy, parsed.language).map_err(|e| e.to_string())?;
    }
    Ok(true)
}

/// Formata um arquivo, ou os `.strig` de um diretório (sem descer em subdiretórios). Com `check`
/// nada é escrito. Um arquivo com erro não impede os outros.
///
/// # Errors
/// O caminho não existe ou o diretório não pôde ser listado.
pub fn run(path: &Path, check: bool) -> Result<Report, String> {
    let mut report = Report::default();
    for file in files_of(path)? {
        match one(&file, check) {
            Ok(true) => report.changed.push(file),
            Ok(false) => report.unchanged += 1,
            Err(message) => report.errors.push(message),
        }
    }
    Ok(report)
}
