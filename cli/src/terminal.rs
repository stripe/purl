//! Helpers for safely displaying untrusted text in a terminal.

/// Remove terminal control characters from untrusted text.
///
/// This includes ASCII escape sequences, OSC terminators such as BEL, newlines,
/// and Unicode C1 controls. Callers add any desired formatting themselves.
pub fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Truncate a string at Unicode scalar-value boundaries.
pub fn truncate_end(s: &str, max_chars: usize) -> String {
    let mut chars = s.chars();
    let prefix: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

/// Truncate the middle of a string at Unicode scalar-value boundaries.
pub fn truncate_middle(
    s: &str,
    max_chars: usize,
    prefix_chars: usize,
    suffix_chars: usize,
) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        return chars.into_iter().collect();
    }

    let prefix: String = chars.iter().take(prefix_chars).collect();
    let suffix: String = chars
        .iter()
        .skip(chars.len().saturating_sub(suffix_chars))
        .collect();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_terminal_controls() {
        assert_eq!(sanitize("safe\x1b[2J\x07\ntext\u{0085}"), "safe[2Jtext");
    }

    #[test]
    fn truncation_is_utf8_safe() {
        assert_eq!(truncate_end("abçdéf", 4), "abçd...");
        assert_eq!(truncate_middle("0x12…456789", 8, 6, 4), "0x12…4...6789");
    }
}
