# config.rs

## struct CertGenConfig

It carries NO key material and NO path derived from the INVOKING
IDENTITY, and both omissions are load bearing.

An XDG or home lookup under `sudo` resolves to root's, and would quietly
write root-owned files into the wrong place. A path written out whole is
fine, since sudo resolves what it is given - it is the identity-derived
lookup that is banned, not the elevation. That is why `secret_data`, the
one path a profile holds, must be absolute.

The only secret this tool handles is the key it mints, and that goes
exactly where it is told. What is left is ordinary configuration: safe to
commit, safe to hand-edit, nothing to protect. That is what makes a
profile shippable as text from a consuming project.

### secret_data

The secret DATA home: `install` places the key material under it, at
`<secret_data>/sourcetrait/<name>/certs`, and a consumer finds it there.
It lives in the profile because srcert and every consumer of the material
already read the profile, so one setting answers all of them, and
`--secret-data` overrides it for a single run.

A profile an application ships leaves it unset. The location is the
operator's, and a home nobody named is refused where it is needed, with
the profile to edit.

### validity_days

Defaulted explicitly rather than inheriting the certificate library's
own default, which is not a decision we want made for us somewhere else.

### fn parse

Split out from `load` so the schema is testable without a filesystem, and
so a consuming project can validate profile text BEFORE it is written.
`install_profile` leans on exactly that: it parses first, so a caller
cannot install a profile the tool will then refuse to read.

### fn extended_key_usages

Deduplicated in declaration order rather than sorted, so a profile that
names a usage twice produces the same certificate as one that names it
once, and the order a reader wrote is the order the extension carries.

### fn subject_alt_names

An entry that parses as an IP address becomes an iPAddress alternative
name and everything else a dNSName, which is why a profile does not have
to say which it meant.

The ASCII rejection is ours rather than the certificate library's. A
dNSName must be IA5, and failing here names the offending profile entry;
failing deeper names an encoding.

## struct EntityConfig

### subject_alt_names

This is the field that decides whether a `wss://localhost:<port>` URL
verifies. Hostname verification reads alternative names rather than the
common name, so an address-only list fails a `localhost` URL even though
the socket is identical. Ports are not in certificates at all, so one
leaf covers every local port a service might move between.

### usages

Absent means server alone, which is what a profile written before the
field existed meant. That default is what keeps the field additive.

## enum EntityUsage

A leaf without `Client` cannot be presented as a client certificate, so a
mutual-TLS deployment that reuses a server-only leaf fails at handshake
with an error naming neither the profile nor this field. Declaring it is
what turns that from a discovery into a configuration decision.

This is not hypothetical: it is the whole reason the field exists. The
grammar server's certificates carry server authentication alone, which is
what refuted the plan to reuse them for a mutual-TLS bridge.
