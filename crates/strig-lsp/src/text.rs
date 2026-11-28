//! Positions and words. The language counts columns in characters; the protocol counts UTF-16
//! units, so every position crossing the boundary goes through here.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use lsp_types::{Position, Range, Uri};

/// The UTF-16 offset of the character at index `chars` of `line`.
pub fn utf16_of(line: &str, chars: usize) -> u32 {
    let units: usize = line.chars().take(chars).map(char::len_utf16).sum();
    u32::try_from(units).unwrap_or(u32::MAX)
}

/// The character index of UTF-16 offset `units` in `line`, clamped to the end of the line.
pub fn chars_of(line: &str, units: u32) -> usize {
    let mut seen = 0u32;
    for (at, c) in line.chars().enumerate() {
        if seen >= units {
            return at;
        }
        seen += u32::try_from(c.len_utf16()).unwrap_or(2);
    }
    line.chars().count()
}

fn line_at(text: &str, line: u32) -> &str {
    text.lines().nth(line as usize).unwrap_or("")
}

/// The range of a 1-based `line:column` of `len` characters in `text`.
pub fn range_of(text: &str, line: u32, column: u32, len: u32) -> Range {
    let row = line.saturating_sub(1);
    let text_line = line_at(text, row);
    let from = column.saturating_sub(1) as usize;
    Range {
        start: Position::new(row, utf16_of(text_line, from)),
        end: Position::new(row, utf16_of(text_line, from + len.max(1) as usize)),
    }
}

/// The range covering the whole of `text`.
pub fn whole(text: &str) -> Range {
    let last = text.split('\n').next_back().unwrap_or("");
    let rows = text.matches('\n').count();
    Range {
        start: Position::new(0, 0),
        end: Position::new(
            u32::try_from(rows).unwrap_or(u32::MAX),
            utf16_of(last, last.chars().count()),
        ),
    }
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '.' | '-' | ':' | '#')
}

/// The text of `line` before the cursor.
pub fn before_cursor(text: &str, at: Position) -> String {
    let line = line_at(text, at.line);
    line.chars().take(chars_of(line, at.character)).collect()
}

/// The word under the cursor, with the range it spans.
pub fn word_at(text: &str, at: Position) -> Option<(String, Range)> {
    let line = line_at(text, at.line);
    let chars: Vec<char> = line.chars().collect();
    let cursor = chars_of(line, at.character);
    let mut start = cursor.min(chars.len());
    while start > 0 && is_word(chars[start - 1]) {
        start -= 1;
    }
    let mut end = cursor.min(chars.len());
    while end < chars.len() && is_word(chars[end]) {
        end += 1;
    }
    if start == end {
        return None;
    }
    let word: String = chars[start..end].iter().collect();
    let range = Range {
        start: Position::new(at.line, utf16_of(line, start)),
        end: Position::new(at.line, utf16_of(line, end)),
    };
    Some((word, range))
}

/// The partial word right before the cursor, for completion.
pub fn prefix_at(text: &str, at: Position) -> String {
    let head = before_cursor(text, at);
    let word: Vec<char> = head.chars().rev().take_while(|c| is_word(*c)).collect();
    word.into_iter().rev().collect()
}

const UNRESERVED: &str = "-._~/";

/// `file:///path` for an absolute path.
pub fn uri_of(path: &Path) -> Option<Uri> {
    let raw = path.to_str()?;
    let mut out = String::from("file://");
    if !raw.starts_with('/') {
        out.push('/');
    }
    for byte in raw.replace('\\', "/").bytes() {
        if byte.is_ascii_alphanumeric() || UNRESERVED.contains(char::from(byte)) || byte == b':' {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    Uri::from_str(&out).ok()
}

/// The path of a `file:` URI.
pub fn path_of(uri: &Uri) -> Option<PathBuf> {
    let text = uri.as_str();
    let rest = text.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let mut bytes = Vec::with_capacity(rest.len());
    let raw = rest.as_bytes();
    let mut at = 0;
    while at < raw.len() {
        if raw[at] == b'%' && at + 2 < raw.len() {
            let hex = std::str::from_utf8(&raw[at + 1..at + 3]).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            at += 3;
        } else {
            bytes.push(raw[at]);
            at += 1;
        }
    }
    let decoded = String::from_utf8(bytes).ok()?;
    // `/C:/dir` is a drive path.
    let windows = decoded.len() > 2 && decoded.as_bytes()[2] == b':' && decoded.starts_with('/');
    Some(PathBuf::from(if windows { &decoded[1..] } else { &decoded }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16_counts_astral_characters_as_two() {
        assert_eq!(utf16_of("a😀b", 2), 3);
        assert_eq!(chars_of("a😀b", 3), 2);
    }

    #[test]
    fn word_at_takes_dotted_ids() {
        let (word, range) = word_at("  permission org.read {", Position::new(0, 16)).unwrap();
        assert_eq!(word, "org.read");
        assert_eq!(range.start.character, 13);
    }

    #[test]
    fn uri_round_trips_a_path_with_spaces() {
        let path = PathBuf::from("/tmp/my policy/a.strig");
        let uri = uri_of(&path).unwrap();
        assert_eq!(uri.as_str(), "file:///tmp/my%20policy/a.strig");
        assert_eq!(path_of(&uri), Some(path));
    }
}
