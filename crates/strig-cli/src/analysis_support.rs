//! What `diff` and `lint` share: reading a policy from a directory or a file.

use std::path::Path;

use strig::dsl::fs;
use strig::dsl::{Built, MAX_SOURCE_BYTES, Project};

/// Reads and builds the policy at `path`: a directory of `*.strig` files, or one file.
pub(crate) fn load(path: &str) -> Result<Built, String> {
    let given = Path::new(path);
    let project = if given.is_dir() {
        let project = fs::read_dir(given).map_err(|e| e.to_string())?;
        if project.is_empty() {
            return Err(format!("no *.strig file in `{path}`"));
        }
        project
    } else {
        let text = read_limited(given)?;
        let mut project = Project::new();
        project.add_source(path, &text).map_err(|e| e.to_string())?;
        project
    };
    project.build().map_err(|e| e.to_string())
}

/// Reads a small text file, refusing a link and anything larger than a source may be.
pub(crate) fn read_limited(path: &Path) -> Result<String, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("cannot read `{}`: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("`{}` is not a regular file", path.display()));
    }
    if meta.len() > u64::try_from(MAX_SOURCE_BYTES).unwrap_or(u64::MAX) {
        return Err(format!("`{}` is larger than {MAX_SOURCE_BYTES} bytes", path.display()));
    }
    std::fs::read_to_string(path).map_err(|e| format!("cannot read `{}`: {e}", path.display()))
}
