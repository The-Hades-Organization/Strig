//! Reading and writing policy files: the only part of the language that touches the disk.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::dsl::{MAX_PROJECT_BYTES, MAX_SOURCE_BYTES};
use crate::dsl::{Diagnostics, Language, Parsed, Policy, PrintError, Project, parse, print};

/// The extension of the policy files [`read_dir`] picks up.
pub const EXTENSION: &str = "themis";

/// The most files [`read_dir`] reads from one directory.
pub const MAX_FILES: usize = 1024;

/// Why a file or directory could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FsError {
    /// The operating system refused, or the file is not valid UTF-8 text.
    #[error("cannot access `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The file is larger than [`MAX_SOURCE_BYTES`].
    #[error("`{}` is larger than {MAX_SOURCE_BYTES} bytes", path.display())]
    TooLarge { path: PathBuf },
    /// The directory holds more than [`MAX_FILES`] policy files.
    #[error("`{}` holds more than {MAX_FILES} policy files", path.display())]
    TooManyFiles { path: PathBuf },
    /// A file resolved to a place outside the directory being read.
    #[error("`{}` resolves outside the directory", path.display())]
    Outside { path: PathBuf },
    /// The text is not valid policy.
    #[error(transparent)]
    Syntax(#[from] Diagnostics),
    /// The policy cannot be written in the chosen syntax.
    #[error(transparent)]
    Print(#[from] PrintError),
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> FsError + '_ {
    move |source| FsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn refuse_link(path: &Path) -> Result<(), FsError> {
    let meta = fs::symlink_metadata(path).map_err(io_error(path))?;
    if meta.file_type().is_symlink() {
        return Err(FsError::Outside {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Reads one regular file as text (a link is refused), within the size limit, without a BOM.
fn read_text(path: &Path) -> Result<String, FsError> {
    refuse_link(path)?;
    let file = File::open(path).map_err(io_error(path))?;
    if !file.metadata().map_err(io_error(path))?.is_file() {
        return Err(FsError::Outside {
            path: path.to_path_buf(),
        });
    }
    let mut text = String::new();
    let limit = u64::try_from(MAX_SOURCE_BYTES).unwrap_or(u64::MAX);
    // One byte past the limit tells a file that fits from one that does not.
    file.take(limit.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(io_error(path))?;
    if text.len() > MAX_SOURCE_BYTES {
        return Err(FsError::TooLarge {
            path: path.to_path_buf(),
        });
    }
    if let Some(rest) = text.strip_prefix('\u{feff}') {
        return Ok(rest.to_string());
    }
    Ok(text)
}

/// Reads and validates one policy file. Positions in errors carry the path as given. A link is
/// not followed.
///
/// # Errors
/// [`FsError::Io`], [`FsError::TooLarge`] and [`FsError::Outside`] (a link) for the file,
/// [`FsError::Syntax`] for its content.
pub fn read_file(path: impl AsRef<Path>) -> Result<Parsed, FsError> {
    let path = path.as_ref();
    let text = read_text(path)?;
    Ok(parse(&path.display().to_string(), &text)?)
}

/// Reads every `.themis` file of a directory (not its subdirectories) into a [`Project`], in
/// alphabetical order. Links are not followed and every file must resolve inside the directory.
/// The files hold at most [`MAX_FILES`] and, together, [`MAX_PROJECT_BYTES`] bytes.
///
/// The project is not built: call [`Project::build`] to merge and validate it.
///
/// # Errors
/// [`FsError::Io`], [`FsError::TooLarge`] (a file, or all of them together),
/// [`FsError::TooManyFiles`], [`FsError::Outside`] and,
/// for the content, [`FsError::Syntax`].
pub fn read_dir(path: impl AsRef<Path>) -> Result<Project, FsError> {
    let dir = path.as_ref();
    let base = dir.canonicalize().map_err(io_error(dir))?;
    let mut files = Vec::new();
    for entry in fs::read_dir(&base).map_err(io_error(dir))? {
        let entry = entry.map_err(io_error(dir))?;
        let file_type = entry.file_type().map_err(io_error(dir))?;
        let name = PathBuf::from(entry.file_name());
        if !file_type.is_file() || name.extension().is_none_or(|e| e != EXTENSION) {
            continue;
        }
        if files.len() == MAX_FILES {
            return Err(FsError::TooManyFiles {
                path: dir.to_path_buf(),
            });
        }
        files.push(name);
    }
    files.sort();
    let mut project = Project::new();
    let mut total = 0usize;
    for name in files {
        let resolved = base.join(&name).canonicalize().map_err(io_error(dir))?;
        if !resolved.starts_with(&base) {
            return Err(FsError::Outside { path: resolved });
        }
        let text = read_text(&resolved)?;
        total = total.saturating_add(text.len());
        if total > MAX_PROJECT_BYTES {
            return Err(FsError::TooLarge {
                path: dir.to_path_buf(),
            });
        }
        project.add_source(&dir.join(&name).display().to_string(), &text)?;
    }
    Ok(project)
}

/// Writes a policy as text in the given syntax, comments included. An existing file is replaced
/// as a whole: the text goes to a new file beside it and is renamed over it, so a failure leaves
/// the old file as it was. A destination that is a link is refused, not followed.
///
/// # Errors
/// [`FsError::Print`] when the syntax cannot say the policy, [`FsError::Outside`] when the
/// destination is a link, [`FsError::Io`] when the write fails.
pub fn write_file(path: impl AsRef<Path>, policy: &Policy, language: Language) -> Result<(), FsError> {
    let path = path.as_ref();
    let text = print(policy, language)?;
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(FsError::Outside {
                path: path.to_path_buf(),
            });
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(path)(e)),
    }
    let Some(name) = path.file_name() else {
        return Err(io_error(path)(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path names no file",
        )));
    };
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".{}.tmp", std::process::id()));
    let temp = path.with_file_name(temp_name);
    let written = (|| {
        // `create_new` never follows a link planted at the temporary name.
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if let Err(source) = written {
        // The write already failed: a leftover temporary file is not worth a second error.
        fs::remove_file(&temp).ok();
        return Err(FsError::Io {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}
