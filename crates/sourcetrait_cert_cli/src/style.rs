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
    pub(crate) fn colour(self) -> anstyle::Style {
        let colour = match self {
            Self::Info => anstyle::AnsiColor::Blue,
            Self::Done => anstyle::AnsiColor::Green,
            Self::Ask => anstyle::AnsiColor::Yellow,
            Self::Fail => anstyle::AnsiColor::Red,
        };
        anstyle::Style::new().fg_color(Some(colour.into()))
    }

    /// Attention and failure go to stderr; results go to stdout.
    fn to_stderr(self) -> bool {
        matches!(self, Self::Ask | Self::Fail)
    }
}

/// A resource named inside a sentence.
fn resource_style() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::Cyan.into()))
}

/// Supporting detail: a listed item, or a question's default.
fn dim_style() -> anstyle::Style {
    anstyle::Style::new().fg_color(Some(anstyle::AnsiColor::BrightBlack.into()))
}

/// Wrap in colour, or not, as the caller has already decided.
pub(crate) fn paint(style: anstyle::Style, text: &str, colour: bool) -> String {
    if !colour {
        return text.to_string();
    }
    format!("{}{text}{}", style.render(), style.render_reset())
}

/// A path with the home prefix collapsed, for reading rather than use.
pub fn pretty_path(path: &Path) -> String {
    collapse_home(&path.display().to_string(), std::env::var("HOME").ok().as_deref())
}

/// Collapse the home prefix wherever it appears, boundary-aware.
pub(crate) fn collapse_home(text: &str, home: Option<&str>) -> String {
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

/// A resource, styled and home-collapsed, for a message body.
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

fn stream_is_terminal(kind: Kind) -> bool {
    if kind.to_stderr() {
        std::io::stderr().is_terminal()
    } else {
        std::io::stdout().is_terminal()
    }
}

/// A message, prefixed and coloured, split across its own lines.
pub fn line(kind: Kind, message: &str) {
    let lines: Vec<String> = message.lines().map(str::to_string).collect();
    if lines.is_empty() {
        emit(kind, &[String::new()]);
        return;
    }
    emit(kind, &lines);
}

/// A headline with its results listed beneath it, one per line.
pub fn report(kind: Kind, headline: &str, items: &[String]) {
    let colour = stream_is_terminal(kind);
    let mut lines = vec![headline.to_string()];
    for item in items {
        lines.push(format!("- {}", paint(dim_style(), item, colour)));
    }
    emit(kind, &lines);
}

/// Emit prefixed lines, collapsing any home path they carry.
fn emit(kind: Kind, lines: &[String]) {
    let colour = stream_is_terminal(kind);
    let home = std::env::var("HOME").ok();
    let prefix = prefix(kind, colour);
    let text: String = lines
        .iter()
        .map(|line| format!("{prefix} {}\n", collapse_home(line, home.as_deref())))
        .collect();
    if kind.to_stderr() {
        let _ = std::io::stderr().write_all(text.as_bytes());
    } else {
        let _ = std::io::stdout().write_all(text.as_bytes());
    }
}

/// The option group: all of it dim, the default bold within it.
pub(crate) fn options(colour: bool) -> String {
    format!(
        "{}{}{}",
        paint(dim_style(), "[yes/", colour),
        paint(dim_style().bold(), "no", colour),
        paint(dim_style(), "]", colour),
    )
}

/// Ask before something the answer cannot be taken back from.
pub fn confirm(question: &str) -> bool {
    let colour = std::io::stderr().is_terminal();
    let mut err = std::io::stderr();
    let _ = write!(
        err,
        "{} {question} {} ",
        prefix(Kind::Ask, colour),
        options(colour),
    );
    let _ = err.flush();

    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    accepted(&answer)
}

/// Trimmed and case-folded, and it must be the whole word.
pub(crate) fn accepted(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("yes")
}
