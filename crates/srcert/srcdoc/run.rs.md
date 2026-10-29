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

A verb with more than one thing to act on nests nouns under it:
`srcert generate entity <profile>`, the verb, then the noun, then the
profile.

## enum Generate

`generate` takes what it mints as a noun: `all`, an authority and the leaf
it signs in one shot, the directory `install` reads; `authority`, the CA
alone; and `entity`, a leaf under an EXISTING authority, for the
one-CA-many-hosts model. A new kind of material is a new noun under the
one verb rather than a hyphenated verb of its own (the_user), and each
noun keeps its own `profile` positional per the convention above.

Each noun takes its files in one of two forms. The dir form names parents,
`certs` leaves under them holding srcert's own file names. The file form
names the files themselves, `--authority-cert` and `--authority-key`, and
`--entity-cert` and `--entity-key` where an entity is minted, for material
kept under names of its own (the_user). The forms are exclusive and a file
form is named whole: a part of one, or both forms at once, is refused
before anything is read.

`entity`'s dir form takes two dirs - the authority dir to read the CA
from, and the output dir for the new leaf - because a leaf carries the
fixed `entity_<name>` filename, so a second one lands in its own dir
rather than over the first.

## fn named_authority / fn named_files

`None` is the dir form and `Some` the file form, so each command matches
the two forms against its dirs in one place. `named_files` refuses a part
of the authority's pair with the four flags' message, naming the whole it
belongs to.

## fn generate

One dispatch for the nouns, so each still names its own attempt in a
failure's line, as every verb does through `failing`.

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

## fn resolve_secret_data

`--secret-data` for one run, else the profile's `secret_data`, else a
refusal naming the profile to edit. There is no environment default: the
profile is the one place srcert and every consumer of the material read,
so a location set anywhere else is one they could disagree on.

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
