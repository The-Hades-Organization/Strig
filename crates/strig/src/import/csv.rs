//! The small CSV both importers read: comma separated, fields trimmed, `"` quotes a field that
//! holds a comma, `#` at the start of a line is a comment.

/// One field and the column where it starts (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Field {
    pub text: String,
    pub column: u32,
}

/// One line of fields and its number (1-based).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    pub line: u32,
    pub fields: Vec<Field>,
}

pub(crate) fn column(at: usize) -> u32 {
    u32::try_from(at.saturating_add(1)).unwrap_or(u32::MAX)
}

pub(crate) fn line_number(at: usize) -> u32 {
    u32::try_from(at.saturating_add(1)).unwrap_or(u32::MAX)
}

/// Reads `text` into records; blank lines and comments are skipped.
///
/// # Errors
/// The line, column and reason of a quote that never closes.
pub(crate) fn parse(text: &str) -> Result<Vec<Record>, (u32, u32, String)> {
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = line_number(index);
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let chars: Vec<char> = raw.chars().collect();
        let mut fields = Vec::new();
        let mut at = 0;
        loop {
            while chars.get(at).is_some_and(|c| c.is_whitespace()) {
                at += 1;
            }
            let start = at;
            let mut value = String::new();
            if chars.get(at) == Some(&'"') {
                at += 1;
                loop {
                    match chars.get(at) {
                        None => return Err((line, column(start), "a quoted field is never closed".to_string())),
                        Some('"') if chars.get(at + 1) == Some(&'"') => {
                            value.push('"');
                            at += 2;
                        }
                        Some('"') => {
                            at += 1;
                            break;
                        }
                        Some(c) => {
                            value.push(*c);
                            at += 1;
                        }
                    }
                }
                while chars.get(at).is_some_and(|c| c.is_whitespace()) {
                    at += 1;
                }
            } else {
                while chars.get(at).is_some_and(|c| *c != ',') {
                    value.push(chars[at]);
                    at += 1;
                }
                value = value.trim_end().to_string();
            }
            fields.push(Field {
                text: value,
                column: column(start),
            });
            match chars.get(at) {
                Some(',') => at += 1,
                Some(_) => return Err((line, column(at), "unexpected text after a quoted field".to_string())),
                None => break,
            }
        }
        out.push(Record { line, fields });
    }
    Ok(out)
}
