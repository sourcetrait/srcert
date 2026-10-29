# verify.rs

## fn verify

Answers two questions that fail independently: did the CA actually become
trusted, and can the unprivileged user READ the keys it will need at
runtime.

THE KEY CHECK READS RATHER THAN STATS, and that is the whole point of the
function. `install` elevates individual commands, and a stat succeeds
regardless of ownership - so a stat-based check passes on a root-owned
key the service cannot open. Run this AS THE INVOKING USER, never under
sudo, or it proves nothing at all: under sudo it reads keys as root and
reports success for a runtime that will fail.

BOTH private keys are read, not just the authority's. The server serves
TLS with the ENTITY key, so checking only the authority key would pass
while the key actually used at runtime was unreadable.

## fn read_trusted_set

The two trust models differ only in HOW the text is obtained, so the
comparison below stays shared rather than being written twice.

## fn contains_cert

Compared on the base64 body with all whitespace stripped, because the
store's copy is REGENERATED rather than byte-copied: wrapping and
surrounding commentary differ, so a literal PEM substring test reports a
false negative on a perfectly good install.
