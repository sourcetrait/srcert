# generate.rs

## enum CertFileKind

`generate` knows nothing about destinations on purpose. `install` owns
every placement decision, so there is exactly one place to look when
asking where a file ends up, rather than the logic being smeared across
both halves.

## fn certs_dir

Every path argument this tool takes names a PARENT, and we own the
`certs` leaf under it. So a caller passes the location it wants involved
and never has to know our filenames, and the same directory can be handed
to `generate`, `install` and `verify` without any of them meaning
something subtly different by it.

The one place this does NOT apply is the system trust directory, which
has its own contract with the platform's refresh command - a `certs`
subdirectory there would simply not be picked up. That path is used
exactly as given.

## fn secret_certs_dir

The vendor and application segments are not decoration. The secret data
home belongs to the box rather than to us, so dropping a bare `certs`
directory at its root would collide with every other application that
ever wants one. The application segment is the profile's own name, which
is what keeps two profiles from installing over each other.

## struct CertFiles

### fn write

Takes the four PEM strings rather than the live certificate-library
values. The reference implementation needed a self-referencing struct
here, because the certified issuer borrows the keypair and the writer
wanted both afterwards. Generation, signing and writing all happen in one
scope, so taking the already-serialized PEMs removes the self-reference -
and with it a proc-macro dependency, which matters for a binary whose
whole justification is a small blast radius.

## fn restrict

Private keys go 0600. The staging directory is already 0700, so this is
redundant today; it is kept because a key that becomes readable the
moment someone widens the directory is a latent mistake, and the cost is
one syscall at mint time.

## fn generate

AN EXISTING `certs` DIRECTORY IS A HARD ERROR, NOT A NO-OP. The reference
guarded on "all four artifacts present" and skipped, which is the
dangerous shape: a partially populated directory would regenerate over
live material, and a fully populated one would silently do nothing while
the caller believed it had fresh certificates. Refusing makes the
operator decide, so neither a stale authority nor an anchor rotated out
from under a running service can happen by accident.

ECDSA P-256 FOR BOTH KEYS. It is the conservative pick for client
compatibility, where ed25519 would have been a gamble against whatever
TLS stack the peer happens to ship.

The authority key identifier extension on the leaf is set deliberately.
Without it the chain does not build for some verifiers, which is easy to
omit and tedious to diagnose, because the failure is at the far end of a
handshake and names nothing local.

## fn validity_window

Carried an ECDSA note in an earlier revision, which described `generate`
rather than this function. The note is above; this computes a window.

## fn create_staging_dir

Created 0700 EXPLICITLY rather than inheriting the caller's umask,
because the directory holds CA private key material for the moments
between minting and installing.

## fn leaf_params

Extracted from `generate` so `generate` and `generate_entity` build the
leaf identically. The profile is the single source of what a leaf carries
(CN, SANs, usage EKUs, validity), so the two mint paths cannot drift on
it. The authority-key-identifier extension is set here, so a leaf from
either path carries its AKI.

## struct EntityFiles

The entity-only counterpart to `CertFiles`: two paths, not four. A host
joining a shared authority holds its own leaf and the peers' public
leaves it pins - never the CA private key, which stays with the authority
holder. So `generate_entity` writes only `entity_<name>.{,key.}pem`, and
this names them. `write` restricts the private key 0600 exactly as
`CertFiles::write` does.

## fn generate_entity

Mints a leaf under an EXISTING authority, for the one-CA-many-hosts
model: all internal endpoints chain to one authority and each is pinned
by its specific leaf (entity-pin), so a shared CA plus per-host leaves is
the shape. `generate` mints CA+leaf in one shot and cannot add a second
leaf; this reads the CA back and signs.

The CA loads straight from PEM: `KeyPair::from_pem` for the key, then
`rcgen::Issuer::from_ca_cert_pem(cert_pem, ca_key)` builds the issuer by
x509-parsing the cert - no `CertificateParams` rebuild. That needs
rcgen's non-default `x509-parser` feature (enabled on the workspace dep).
`from_ca_cert_pem` re-derives the issuer DN, key usages, and key-id method
(the CA's own SKI, as PreSpecified) from the loaded cert, which is why the
leaf's `use_authority_key_identifier_extension` in `leaf_params` yields a
correct AKI. The returned `Issuer<'static, _>` owns everything, so no
borrow/self-reference concern (unlike the reference impl's ouroboros).

Refuses a missing authority (`UnrecognizedCertSources`) and an existing
output certs dir (`CertsDirExists`, as `generate` does). Output is the two
`EntityFiles`; the CA public is not copied - a host bundle is minted per
host and the CA public distributed separately for the trust install.
