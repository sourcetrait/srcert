# store.rs

## enum TrustStore

A fieldful enum because the MODELS differ, not merely the paths. A Linux
store is a directory you drop a certificate into plus a refresh command;
macOS hands it to a program and has no such directory. A struct with an
optional directory would have made every consumer re-derive which of the
two it was looking at.

### fn present

The same existence check that stops us writing blindly is what identifies
the platform. That is deliberate reuse rather than a coincidence: a store
we cannot see is a store we must not write to, and a store we can see is
evidence of which platform this is.

### const KNOWN

Ordered, and the order is the answer on a box carrying more than one.
The first present store wins, so the distribution-native anchors sit
ahead of the generic `/usr/local` directory.

## struct TrustDirStore

### cert_extension

Per-store rather than global because one refresh command processes only
`.crt` while another takes `.pem`. Getting this wrong installs a file
that is silently never read, which is the failure this whole family is
shaped to avoid.

## fn resolve_target

Each command resolves ONLY its own fields, and that is a fix rather than
a style. An earlier cut shared one resolver between installing and
verifying, so `install --trust-dir` demanded a `--bundle` it does not
expose and could not be run at all on a keychain platform.

## fn resolve_source

A `--bundle` on a keychain platform is an ERROR rather than silently
dropped, because a flag that is accepted and ignored teaches the operator
that it worked.
