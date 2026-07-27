//! Output locks: what collapses, what accepts, and when colour appears.
use crate::style::{
    Kind,
    accepted,
    collapse_home,
    paint,
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

/// The stream test decides whether escapes appear at all, so both
/// branches are locked rather than only the coloured one.
#[test]
fn colour_is_emitted_only_when_it_is_asked_for() {
    let style = Kind::Info.colour();
    let painted = paint(style, "x", true);
    assert!(painted.contains('\u{1b}'), "an escape is emitted: {painted:?}");
    assert!(painted.contains('x'));
    assert_eq!(paint(style, "x", false), "x");
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
