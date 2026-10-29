SourceTrait Cert
================================================================================
[![License Badge]][License] [![AI Badge]][AI]

*Local TLS certificate authority tooling, driven by named profiles*


Overview
--------------------------------------------------------------------------------

`srcert` mints a local certificate authority and one leaf signed by it,
installs the key material, and makes the system trust the authority. It exists
so that a service on a single machine can be given a real TLS identity without
a public authority and without hand-run OpenSSL recipes.

Every command names a PROFILE, and there is no built-in fallback:

```
srcert show <profile>
srcert generate <profile> <dir>
srcert install <profile> <dir>
srcert verify <profile>
```

What a certificate says is a per-application decision, so an unnamed run would
be minting something nobody chose. Profiles live at
`<config>/sourcetrait/srcert/profiles/<name>.toml`, the configuration home
`$UENV_USR_CONFIG` or else `$XDG_CONFIG_HOME`, with a reference copy under
`default/profiles/` that the tool never reads.

A profile declares what the leaf may be presented AS. A leaf carrying both
usages can sit at either end of a mutual-TLS handshake:

```toml
name = "example"
organization = "Example Org"
validity_days = 3650

[authority]
common_name = "Example Local CA"

[entity]
common_name = "localhost"
subject_alt_names = ["127.0.0.1", "::1", "localhost"]
usages = ["server", "client"]
```

Omitting `usages` means server authentication alone, which is what a profile
written before the field existed meant.

An installed profile names `secret_data`, the absolute directory the key
material lives under, at `<secret_data>/sourcetrait/<name>/certs`: `install`
places it there and `verify` reads it there, and `--secret-data` overrides it
for one run. A profile an application ships leaves it unset, since the location
is the operator's.


Crates
--------------------------------------------------------------------------------

### [Library](./crates/sourcetrait_cert_lib)

*Generation, installation, verification, and profile management*

The library is the integration point rather than a detail of the binary. A
consuming project calls it at startup: if its profile is absent it ships one
through `install_profile`, tells its user to run `srcert` against that name,
and shuts down. That keeps certificate generation an explicit operator act
while letting an application own knowing what its own profile should say.

### [Command line](./crates/sourcetrait_cert_cli)

*`srcert`, the command line over the library*


Operation
--------------------------------------------------------------------------------

`generate` is unprivileged and refuses an existing `certs` directory rather
than regenerating over live material.

`install` runs UNPRIVILEGED and elevates only the individual standard commands
that touch the system trust store. Do not run the whole tool under `sudo`: its
secure path does not include a Cargo install home, and elevation would create
root-owned key material. Its prompt is interactive.

`verify` must run as the invoking user. It READS both private keys rather than
stating them, because a stat succeeds on a key the runtime user cannot open, so
running it elevated proves nothing.


AI
--------------------------------------------------------------------------------

This workspace is iteratively AI authored. It is essentialy tooling for AI, by
AI.


Repository
--------------------------------------------------------------------------------

Found a bug? Let us know! Upvote an existing issue on GitHub or create one if it
doesn't exist.

### Contributors
Contributors, please review [SOURCETRAIT.md](./SOURCETRAIT.md).

#### Copyright Assignment Agreement (CAA)
By committing to this repository you agree to assign to
[Asmov LLC](https://asmov.software) all right, title, and interest worldwide in
all copyright covering your contribution.


License (AGPL3)
--------------------------------------------------------------------------------
SourceTrait Cert: Local TLS certificate authority tooling, driven by named profiles  
Developed by [SourceTrait](https://sourcetrait.com), a division of **Asmov LLC**  
Copyright (C) 2026 [Asmov LLC](https://asmov.software)  

This program is free software: you can redistribute it and/or modify
it under the terms of the **GNU Affero General Public License** as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a [copy](./LICENSE-AGPL-3.txt) of the
GNU Affero General Public License along with this program.
If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).


External dependency licenses are listed in:  
[`LICENSES-EXTERNAL.txt`](./LICENSES-EXTERNAL.txt)

[License]: #License-AGPL3
[License Badge]: https://img.shields.io/badge/license-AGPL3-blue.svg
[AI]: #AI
[AI Badge]: https://img.shields.io/badge/ai-authored-green.svg
