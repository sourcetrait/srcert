# run.rs

## struct Cli

EVERY COMMAND NAMES ITS PROFILE FIRST, and there is no built-in fallback.
That is the point of the tool rather than an inconvenience: what a
certificate says is a per-application decision, so a run that did not
name a profile would be minting something nobody chose.

The profile is a positional ahead of the subcommand, so the shape reads
`srcert <profile> <command>` - the profile scopes the whole invocation
rather than being an option one command might forget to accept.

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

Prints which trust store was detected, or that it came from arguments,
before doing anything. On a box with more than one candidate store that
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
