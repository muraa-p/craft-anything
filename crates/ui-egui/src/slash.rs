//! Slash commands in a project's prompt box: `/btw where are the files?`. A new command is a
//! [`Command`] and a row in [`COMMANDS`].

/// What a command does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Ask about the build without building (see `just_ask`).
    Btw,
}

/// Every command, by the name typed after the slash.
const COMMANDS: &[(&str, Command)] = &[("btw", Command::Btw)];

/// How a message reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Typed<'a> {
    /// Not a command: it goes as written.
    Message,
    /// A command, and what follows it.
    Command(Command, &'a str),
    /// Shaped like a command, but there's none of that name. It's stopped rather than sent, so a
    /// typo doesn't start a build.
    Unknown(&'a str),
}

/// The command part of a typed message and what follows it: the words after the leading `/`, before
/// the first whitespace, or the whole rest when there's none after the slash. `None` when it isn't
/// shaped like a command, so a path ("/usr/bin is missing") or a plain message isn't one.
fn split_command(text: &str) -> Option<(&str, &str)> {
    let rest = text.trim().strip_prefix('/')?;
    let (name, what) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    // A path isn't a command; a bare "/" has no name yet, so it's still being typed.
    if !name.is_empty() && !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    Some((name, what))
}

pub fn read(text: &str) -> Typed<'_> {
    let Some((name, what)) = split_command(text) else { return Typed::Message };
    if name.is_empty() {
        return Typed::Message;
    }
    match COMMANDS.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
        Some((_, command)) => Typed::Command(*command, what.trim()),
        None => Typed::Unknown(name),
    }
}

/// The commands a typed message could be, as `/name` each: every command when nothing is typed after
/// the slash, the ones starting with the part typed so far. `None` when what they typed isn't a
/// command being typed (a path, a plain message) or is already a complete command, its question
/// after it (`/btw where are the files?`).
pub fn completions(text: &str) -> Option<Vec<String>> {
    let (name, what) = split_command(text)?;
    if !what.trim().is_empty() || COMMANDS.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
        // A command with its question after it is complete; a bare command is complete too.
        return None;
    }
    let lower = name.trim().to_ascii_lowercase();
    Some(COMMANDS.iter().filter(|(n, _)| lower.is_empty() || n.to_ascii_lowercase().starts_with(lower.as_str())).map(|(n, _)| format!("/{}", n)).collect())
}

/// Complete a typed command to its `/name`, keeping what follows it: `/b` → `/btw`, `/b where is it`
/// → `/btw where is it`. `None` when nothing is typed yet or more than one command starts with it.
pub fn complete(text: &str) -> Option<String> {
    let (name, what) = split_command(text)?;
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() || COMMANDS.iter().any(|(n, _)| n.eq_ignore_ascii_case(&lower)) {
        // Nothing typed yet, or already a command: nothing to complete.
        return None;
    }
    let matches: Vec<&str> = COMMANDS.iter().filter(|(n, _)| n.to_ascii_lowercase().starts_with(lower.as_str())).map(|(n, _)| *n).collect();
    let first = matches.first()?;
    if matches.len() > 1 {
        return None;
    }
    Some(format!("/{}{}", first, if what.trim().is_empty() { "".to_string() } else { format!(" {}", what.trim()) }))
}

/// The commands, to say what can be typed: "/btw".
pub fn names() -> String {
    COMMANDS.iter().map(|(n, _)| format!("/{n}")).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_is_a_known_name_after_a_slash() {
        assert_eq!(read("/btw where are the files"), Typed::Command(Command::Btw, "where are the files"));
        assert_eq!(read("  /BTW\n where?  "), Typed::Command(Command::Btw, "where?"));
        assert_eq!(read("/btw"), Typed::Command(Command::Btw, ""));
        assert_eq!(read("/bwt where are the files"), Typed::Unknown("bwt"));
    }

    #[test]
    fn a_path_or_a_slash_in_a_sentence_is_a_message() {
        for text in ["make it blue", "use a/b testing", "/usr/bin is missing", "/", "/ a space", "/src/main.rs crashes"] {
            assert_eq!(read(text), Typed::Message, "{text}");
        }
    }

    #[test]
    fn typing_a_slash_lists_the_commands_it_might_be() {
        assert_eq!(completions("/"), Some(vec!["/btw".to_string()]));
        assert_eq!(completions("/b"), Some(vec!["/btw".to_string()]));
        // A command is complete once its question follows it, so nothing is listed for it.
        assert_eq!(completions("/btw where are the files"), None);
        assert_eq!(completions("/btw"), None);
        assert_eq!(completions("/BTW"), None, "a command is complete in any case");
        // A path or a plain message is not a command being typed.
        assert_eq!(completions("make it blue"), None);
        assert_eq!(completions("/usr/bin is missing"), None);
    }

    #[test]
    fn tab_completes_a_typed_command_and_keeps_what_follows() {
        assert_eq!(complete("/b"), Some("/btw".to_string()));
        assert_eq!(complete("/B where is it"), Some("/btw where is it".to_string()));
        assert_eq!(complete("/"), None, "nothing typed yet can't be completed to one");
        assert_eq!(complete("/btw"), None, "a command is already complete");
        assert_eq!(complete("make it blue"), None, "not a command");
    }
}
