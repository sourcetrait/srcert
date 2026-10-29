# error.rs

## enum CertError

Every variant that wraps an underlying failure KEEPS its source rather
than flattening it to a message. Certificate work is exactly where the
cause matters: "generation failed" is useless next to the certificate
library's own error saying which parameter was rejected, and an install
that cannot read a key needs to distinguish a missing file from a
permission denial.

That choice has one downstream cost worth knowing. Keeping sources makes
the largest variant around 144 bytes, so a consumer carrying `CertError`
directly inside its own error enum trips `clippy::result_large_err` and
has to box it. That is the right trade here - the caller pays one
allocation on a failing path, and the operator gets a cause.

### MissingProfile

Names both the profile and the path it was expected at, and points at the
listing command. There is no fallback profile by design, so this error is
the normal first contact a new consumer has with the tool, and it has to
teach rather than merely report.

### InvalidProfileName

A name is refused rather than sanitised. A cleaned name would address a
different profile than the one asked for, which is worse than an error
because it succeeds.
