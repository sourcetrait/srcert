# lib.rs

The crate splits into a library and a command line because a consuming
project calls the LIBRARY at startup: if its certificate profile is
absent it writes one, tells its user to run `srcert` against that name,
and shuts down. Profile management is therefore public API rather than a
command-line concern, which is what `install_profile` exists for.

The module set follows the lifecycle rather than the type system -
`generate` mints, `install` places and trusts, `verify` answers whether
that worked, `profile` decides which parameters were used, `store` knows
what a platform's trust model is. Each is one stage an operator can name.

## pub use

The face is wider than the binary needs, deliberately. The binary is one
consumer and a daemon calling `install_profile` at startup is another,
and the second reaches for profile paths and the entity types to report
what it placed.

`CertGenConfig` is reachable at `config::CertGenConfig` rather than
through this block. That is not an oversight and not quite a decision:
the type is the profile schema, so a consumer that wants to validate
shipped text before writing it does need it, and it belongs in the face
the next time the list is chosen deliberately.
