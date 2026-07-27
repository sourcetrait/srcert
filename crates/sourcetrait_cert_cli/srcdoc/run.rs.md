# run.rs

## struct Cli

EVERY COMMAND NAMES A PROFILE, and there is no built-in fallback. That is
the point of the tool rather than an inconvenience: what a certificate
says is a per-application decision, so a run that did not name a profile
would be minting something nobody chose.

THE VERB COMES FIRST: `srcert install quest <dir>`. The profile is a
positional on each subcommand rather than one ahead of them all, which is
a correction (the_user) to an earlier shape that read
`srcert <profile> <command>`. Verb-first is how every neighbouring tool
reads, and the repetition across four variants is the price of that.

The cost is real and worth knowing rather than discovering: a new
subcommand has to remember its own `profile` positional, where the old
shape made it structurally impossible to forget. Nothing enforces it, so
it is a convention the next variant has to follow.

## struct Failed

Carries the ATTEMPT beside the cause, so a reported line reads
`Unable to <what>: <cause>`. Neither half knows the other on its own: the
error says why it stopped and only the dispatch knows which verb ran, so
they are composed at the one place holding both rather than every error
in the library learning to phrase itself that way.

The cause is boxed because `CertError` keeps its own sources and is
around 136 bytes, which trips the large-error lint at the standing
zero-warning bar. One allocation on a path that is already failing.

## fn report

Most causes read as `Unable to <what>: <cause>`. A cause that deserves
its own wording is matched here rather than being phrased inside the
library, because the wording is presentation and the library's `Display`
has to stay plain, comparable and free of escape codes.

Matching one variant does not generalise, and that is fine: the default
arm covers everything, and a second bespoke case is another arm rather
than a mechanism.

## const SECRET_DATA_ENV

sudo's environment reset strips it, so an elevated run needs the
preserving flag or the explicit argument. That is a note about how this
tool is MISUSED rather than how it is used: `install` runs unprivileged
and elevates individual commands, so the variable is read by the
invoking user's process and the reset never happens on the sanctioned
path.

## fn resolve_secret_data

Returns the path AND where it came from, because the library treats the
two differently: an explicit argument must already have a parent, while
the environment default is our own namespace and ours to create. Losing
that distinction here would turn a typo into a conjured tree.

## fn cmd_install

THE PREFLIGHT RUNS BEFORE ANYTHING IS PRINTED OR ASKED. The library
checks again for itself, so this call exists purely so that a run which
cannot succeed fails before the operator is asked to authorise an
elevation for it. It also means a failed install says nothing about the
trust store, which is the right amount to say.

Prints which trust store was detected, or that it came from arguments,
once the run is known to be able to proceed. On a box with more than one candidate store that
line is the only way to tell which set of anchors an install actually
went into.

Staging being kept is reported on stderr rather than raised, matching the
library: the install succeeded, and what is left is a CA private key the
operator now has to deal with.

## fn cmd_verify

A failed trust check is an ERROR rather than a printed verdict, so the
exit code carries it. This is the command a deployment script runs, and a
zero exit beside a printed "not trusted" is exactly the shape that gets
ignored.
