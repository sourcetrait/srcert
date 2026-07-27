//! Human-facing output: one prefixed line per message, kind-coloured.
use std::io::{
    IsTerminal,
    Write,
};
use std::path::Path;

/// The binary this output speaks for.
const NAME: &str = "srcert";

/// What a line is doing, which decides its prefix colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Ordinary narration.
    Info,
    /// Finished, succeeded, passed.
    Done,
    /// Your input is about to be needed.
    Ask,
    /// Could not.
    Fail,
}

impl Kind {
    fn colour(self) -> anstyle::Style {
        let colour = match self {
            Self::Info => anstyle::AnsiColor::Blue,
            Self::Done => anstyle::AnsiColor::Green,
            Self::Ask => anstyle::AnsiColor::Yellow,
            Self::Fail => anstyle::AnsiColor::Red,
        };
        anstyle::Style::new().fg_color(Some(colour.into()))
    }

    /// Attention and failure go to stderr so a redirect keeps them visible.
    fn to_stderr(self) -> bool {
        matches!(self, Self::Ask | Self::Fail)
    }
}

/// A resource named inside a sentence.
fn resource_style() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Cyan.into()))
}

/// Supporting detail: a listed item, or the default of a question.
fn dim_style() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::BrightBlack.into()))
}

fn paint(style: anstyle::Style, text: &str, colour: bool) -> String {
    if !colour {
        return text.to_string();
    }
    format!("{}{text}{}", style.render(), style.render_reset())
}

/// A path with the home prefix collapsed, for reading rather than for use.
pub fn pretty_path(path: &Path) -> String {
    collapse_home(&path.display().to_string(), std::env::var("HOME").ok().as_deref())
}

/// Collapse the home prefix WHEREVER it appears, not only at the start.
///
/// A cause built by the library carries its path mid-sentence, so a
/// leading-only rule would leave the most-read line uncollapsed. Split
/// from `pretty_path` so it is testable without an environment.
fn collapse_home(text: &str, home: Option<&str>) -> String {
    let Some(home) = home else {
        return text.to_string();
    };
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return text.to_string();
    }

    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(home) {
        let (before, tail) = rest.split_at(at);
        let after = &tail[home.len()..];
        out.push_str(before);
        // Only a path boundary counts, or `/home/boxer` collapses too.
        if after.is_empty() || after.starts_with('/') {
            out.push('~');
        } else {
            out.push_str(home);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// A resource, styled and home-collapsed, for building a message body.
pub fn resource(path: &Path) -> String {
    paint(
        resource_style(),
        &pretty_path(path),
        std::io::stdout().is_terminal(),
    )
}

/// A resource that is a name rather than a path.
pub fn named(name: &str) -> String {
    paint(resource_style(), name, std::io::stdout().is_terminal())
}

fn prefix(kind: Kind, colour: bool) -> String {
    paint(kind.colour(), &format!("[{NAME}]"), colour)
}

/// A message, prefixed and coloured by kind.
///
/// Split on newlines so that a multi-line cause keeps the prefix on every
/// line and stays attributable when it is read beside other output.
pub fn line(kind: Kind, message: &str) {
    let lines: Vec<String> = message.lines().map(str::to_string).collect();
    if lines.is_empty() {
        emit(kind, &[String::new()]);
        return;
    }
    emit(kind, &lines);
}

/// A headline with its results listed beneath it, one per line.
///
/// The items are dimmed because the headline is the message and they are
/// the enumeration under it.
pub fn report(kind: Kind, headline: &str, items: &[String]) {
    let colour = if kind.to_stderr() {
        std::io::stderr().is_terminal()
    } else {
        std::io::stdout().is_terminal()
    };
    let mut lines = vec![headline.to_string()];
    for item in items {
        lines.push(format!("- {}", paint(dim_style(), item, colour)));
    }
    emit(kind, &lines);
}

/// Every line carries the prefix, so a wrapped report stays attributable.
///
/// The home collapse runs here as well as at `pretty_path`, because a
/// message we did not compose - a cause raised by the library - carries
/// its own paths and would otherwise print them in full.
fn emit(kind: Kind, lines: &[String]) {
    let to_stderr = kind.to_stderr();
    let colour = if to_stderr {
        std::io::stderr().is_terminal()
    } else {
        std::io::stdout().is_terminal()
    };
    let home = std::env::var("HOME").ok();
    let prefix = prefix(kind, colour);
    let text: String = lines
        .iter()
        .map(|line| format!("{prefix} {}\n", collapse_home(line, home.as_deref())))
        .collect();
    if to_stderr {
        let _ = std::io::stderr().write_all(text.as_bytes());
    } else {
        let _ = std::io::stdout().write_all(text.as_bytes());
    }
}

/// Ask before doing something the answer cannot be taken back from.
///
/// The default is refusal, and it is what a non-terminal stdin gets.
pub fn confirm(question: &str) -> bool {
    let colour = std::io::stderr().is_terminal();
    let mut err = std::io::stderr();
    let _ = write!(
        err,
        "{} {question} [yes/{}] ",
        prefix(Kind::Ask, colour),
        paint(dim_style(), "no", colour),
    );
    let _ = err.flush();

    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    accepted(&answer)
}

/// Trimmed and case-folded, and it must be the whole word.
fn accepted(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("yes")
}

#[cfg(test)]
mod tests {
    use super::{
        accepted,
        collapse_home,
    };

    #[test]
    fn the_home_prefix_collapses_and_a_longer_sibling_does_not() {
        assert_eq!(collapse_home("/home/box/a/b", Some("/home/box")), "~/a/b");
        assert_eq!(collapse_home("/home/box", Some("/home/box")), "~");
        assert_eq!(collapse_home("/home/box/", Some("/home/box")), "~/");
        assert_eq!(
            collapse_home("/home/boxer/a", Some("/home/box")),
            "/home/boxer/a",
            "a longer name that merely starts the same is not the home"
        );
        assert_eq!(collapse_home("/etc/ssl", Some("/home/box")), "/etc/ssl");
        assert_eq!(collapse_home("/home/box/a", None), "/home/box/a");
        assert_eq!(collapse_home("/home/box/a", Some("")), "/home/box/a");
    }

    #[test]
    fn a_trailing_separator_on_the_home_does_not_change_the_answer() {
        assert_eq!(collapse_home("/home/box/a", Some("/home/box/")), "~/a");
    }

    /// A cause raised by the library names its path mid-sentence, which a
    /// leading-only rule would leave in full.
    #[test]
    fn a_path_inside_a_sentence_collapses_too() {
        assert_eq!(
            collapse_home("expected /home/box/a.toml. Install one", Some("/home/box")),
            "expected ~/a.toml. Install one"
        );
        assert_eq!(
            collapse_home("/home/box/a and /home/box/b", Some("/home/box")),
            "~/a and ~/b",
            "every occurrence, not only the first"
        );
        assert_eq!(
            collapse_home("see /home/boxer/a here", Some("/home/box")),
            "see /home/boxer/a here",
            "the boundary rule holds mid-sentence as well"
        );
    }

    /// The stream test decides whether escapes are emitted at all, so
    /// both branches are locked rather than only the coloured one.
    #[test]
    fn colour_is_emitted_only_when_it_is_asked_for() {
        let style = super::Kind::Info.colour();
        let painted = super::paint(style, "x", true);
        assert!(painted.contains('\u{1b}'), "an escape is emitted: {painted:?}");
        assert!(painted.contains('x'));
        assert_eq!(super::paint(style, "x", false), "x");
    }

    #[test]
    fn only_the_whole_word_accepts() {
        for yes in ["yes", "YES", " Yes ", "yes\n"] {
            assert!(accepted(yes), "{yes:?}");
        }
        for no in ["", "\n", "y", "Y", "no", "yess", "yes please"] {
            assert!(!accepted(no), "{no:?}");
        }
    }
}
