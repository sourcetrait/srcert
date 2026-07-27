# style.rs

The house convention for human-facing command-line output, which is a
standing development rule rather than this tool's own taste. Every line
carries a bracketed binary name coloured by what the line is doing, and
resources named inside a line are cyan with the home prefix collapsed.

A near-identical copy lives in the daemon's crate in the quest
repository. That duplication is deliberate: the two live in different
repositories, and a shared crate across a repository boundary is exactly
the dependency shape already carried as debt. The copies are behaviourally
the same and differ where each crate's own conventions differ.

## enum Kind

The prefix colour carries SEVERITY and cyan carries NOUNS, which is why an
ordinary blue line still contains cyan. Reading cyan as a fifth severity
is the misreading to avoid.

### fn to_stderr

Attention and failure go to stderr; narration and results go to stdout.
So redirecting stdout to a file keeps the questions and the failures in
front of the operator, which is the split that makes a redirect useful
rather than dangerous.

## fn collapse_home

Split from `pretty_path` so the rule is testable without an environment,
and the rule has one edge worth the test: a longer name that merely
STARTS with the home is not inside it. `/home/boxer/a` under a home of
`/home/box` must not collapse, which a bare prefix comparison gets wrong.
That is the substring-prefix trap in path clothing, and the boundary
check is what closes it.

IT SCANS RATHER THAN STRIPPING A PREFIX, and that was a correction rather
than the first design. A leading-only rule collapsed every path this
command composed and left every path it did NOT - which is exactly the
most-read line, since a cause raised by the library names its path in the
middle of a sentence. The live exercise showed a styled error carrying a
full `/home/box/...`, which is the convention holding for the easy half
only.

So the collapse runs at the emitter as well, over whatever text is about
to be printed. Collapsing an already-collapsed string is a no-op, since
no home substring survives the first pass.

The result is for READING rather than for use. Nothing consumes it back
as a path, and a collapsed path handed to a filesystem call would not
resolve.

## fn paint

Takes the colour decision as an argument rather than testing the stream
itself, which is what makes both branches lockable. The escapes come from
`anstyle`, already in the graph because clap uses it for its own coloured
help, so our lines and `--help` agree about colour without a second
dependency or a second terminal-detection story.

## fn emit

The home collapse runs HERE as well as in `pretty_path`, and that is the
half that was missing. A message this crate composes can collapse its own
paths; a cause raised by the library cannot, and that is the line an
operator reads most often. Collapsing at the emitter covers both, and
collapsing an already-collapsed string is a no-op since no home substring
survives the first pass.

## fn report

The items are dimmed rather than cyan. The headline is the message and
the list is the enumeration beneath it, so the items are supporting detail
in the same sense the default option of a question is. Cyan is for a
resource named INSIDE a sentence.

## fn line

Splits on newlines so a multi-line cause keeps the prefix on every line.
Without that, only the first line of a wrapped error is attributable and
the rest reads as though it came from somewhere else.

## fn options

The whole group is dim and the DEFAULT is bold within it, so `[yes/no]`
reads as one de-emphasised unit while the default still stands out
inside it (the_user's form).

It is built from three separately painted spans rather than one nested
render, and that is a correctness detail rather than a style choice:
re-emitting a colour does NOT clear bold, so a naive nesting leaves the
closing bracket bold. Each span carries its own reset.

The uncoloured form must stay exactly `[yes/no]`, which is locked -
that is the text a reader is being asked to type, and it is what a
non-terminal stream gets.

## fn confirm

The default is refusal, and refusal is also what a non-terminal stdin
gets, since an end-of-input reads as an empty answer. So a scripted run
declines rather than silently elevating, which is the right direction for
this to fail in.

Note the consequence for automation: on a host with passwordless sudo
this prompt becomes the only interactive step in `install`, where sudo's
own prompt would not have been one. No skip flag exists, deliberately -
adding one on speculation is the option-creep the conventions warn about,
and it is one line if it is ever wanted.

## fn accepted

The whole word only. A bare `y` falls through to the default, which is
deliberate friction on a privileged act rather than an oversight.
