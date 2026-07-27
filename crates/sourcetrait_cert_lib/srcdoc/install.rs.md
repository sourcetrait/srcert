# install.rs

## enum SecretData

Where the secret data home came from decides whether we may CREATE it,
and that is the whole reason the origin is carried rather than just the
path.

The environment default is OUR namespace - a sourcetrait extension
nothing else ships - so nobody else will ever make it and creating it
correctly is our job. An explicitly passed path is the CALLER asserting a
location, and a typo there must fail loudly rather than conjure a deep
tree, exactly as for the trust directory.

## fn preflight

Public so a CALLER can run the checks early, and that is the whole
reason it was split out. `install` runs it for itself regardless - a
library cannot depend on having been checked first - so the double call
is deliberate rather than an oversight, and it is a handful of path
tests.

What forced it: the command line asks for elevation before installing,
and an unvalidated prompt asks the operator to authorise something that
was going to fail anyway. Preflight-before-mutation is not enough on its
own, because the prompt sits outside the operation. Every check first,
then ask, then act.

## fn check_exists

The dual of `preflight`, and it sits beside it because the two ask one
question from opposite ends: preflight requires the secret directory to be
ABSENT before installing, this requires its four artifacts to be PRESENT
before a consumer leans on them.

It lives in the library rather than in a consumer because the library owns
the path layout. A daemon reconstructing `secret_certs_dir` plus the four
filenames would duplicate exactly the knowledge this crate exists to hold,
and would then drift the day a filename changes.

PRESENCE IS NOT VALIDITY, and the gap is deliberate rather than unfinished.
It converts a mysterious handshake failure into a clear startup failure for
the two common cases - never minted, and material deleted - and says
nothing about an expired certificate or one that no longer matches the
profile that asked for it. Answering those needs the trust store resolved
too, and a daemon refusing to start because no trust store was detected is
a worse failure mode than the one being prevented, which is why `verify` is
not what a consumer calls at startup.

ALL FOUR ARE REQUIRED, so a partial tree reads absent. A handshake needs
the leaf and its key, and `verify` reads both private keys, so no subset is
a serviceable state - and a caller that treated one as enough would report
ready and fail later.

## fn install

RUNS UNPRIVILEGED, elevating only the few commands that touch the system
trust store. That is what REMOVES the ownership problem rather than
managing it: the key material is created by the invoking user in the
first place, so there is nothing root-owned to hand back and no ownership
change to get wrong afterwards.

THE ORDER IS PREFLIGHT, THEN ACT, and the acting half is ordered so the
reversible work lands first. Key material is placed before the trust step
because key material is the half we can roll back; a failed trust refresh
therefore leaves nothing behind and the command is simply re-runnable.

THE TRUST DIRECTORY MUST ALREADY EXIST. Creating it would turn a typo
into a silent success - a certificate sitting in a directory nothing
reads. A platform-defined path is an assertion the system makes, so the
only correct operation against it is a check.

The CA public certificate is copied into the secret tree alongside the
keys even though it is not secret. `verify` needs a body to look for
whichever trust model took the certificate, and having it beside the keys
means verification does not depend on the staging directory surviving.

Everything inside the secret tree goes go-rwx, public certificates
included. They are not secret in themselves, but a 0644 file sitting
beside a CA key is an inconsistency waiting to be copied by the next
person who adds a file here.

Staging is consumed LAST, deliberately. It still holds a copy of the CA
private key, and leaving it is the kind of duplicate nobody remembers to
clean up - but on any earlier failure it survives intact and the command
re-runs. Moving instead of copying would have taken that away by
destroying the source before the trust step could fail.

## fn consume_staging

A blind recursive remove is the deletion mirror of blindly creating a
system path: the directory came from an argument, so anything else living
in it belongs to someone else. We inventory first, delete the known files
by name, and finish with a plain non-recursive remove - so if anything at
all is left, the removal fails rather than recursing into it.

Keeping staging is NOT an error. The install itself succeeded, and the
caller is told so they can deal with the key material still sitting
there.

## fn create_private_chain

Walks up to the first ancestor that exists, so this covers the secret
data home ITSELF as well as our subdirectories under it. That is right
because it is our own non-standard path and nothing else will have made
it - which is exactly the distinction `SecretData` carries.

Each level is created and chmod'd EXPLICITLY rather than through a
recursive create, which takes its mode from the umask: under root's usual
022 every level came out 0755, a world-traversable directory around a CA
key. The created list is returned newest last so a failure can unwind it.

## fn rollback

Best-effort by design: a rollback failure must not mask the error that
triggered it, because the triggering error is the one the operator can
act on.

## fn trust_file_name

A bare `<name>.pem` in a shared trust directory is the same mistake as a
bare `certs/` in the secret data home. The directory belongs to the box,
so an unqualified name both collides and says nothing about who installed
it.

## fn run_privileged

Two reasons this elevates individual commands rather than expecting to be
run under `sudo`. Running the whole tool elevated cannot resolve at all,
since sudo's secure path does not include our install home, whereas the
standard commands it needs are all on it. And running unprivileged means
the key material is created as the invoking user.

sudo is handed an ARGV, never a shell string: no quoting, no word
splitting, nothing a path containing a space or a quote can turn into a
second command.

Stdio is INHERITED rather than captured, or sudo's password prompt would
be swallowed and the call would appear to hang. That is also why this
path cannot be driven from a non-interactive worker.
