# profile.rs

## fn default_profiles_dir

Nothing reads these. They exist so a user who has customised their
profile can see what the application originally shipped, and restore from
it. That is the entire justification for a second copy, and it is why the
copy is refreshed rather than protected.

## fn config_home

Unlike every path this tool takes as an argument, an environment lookup
is identity-derived. It is safe HERE only because `srcert` is never run
elevated: it runs unprivileged and elevates the few standard commands
that touch the trust store, so the lookup always resolves to the invoking
user. A caller that might itself be elevated passes a path instead.

## struct ProfileInstall

Reports `written` rather than leaving the caller to compare timestamps,
because the two outcomes want different behaviour from a consumer: a
freshly written profile means the operator has not minted anything yet,
while an existing one means they have their own and it was respected.

## fn install_profile

The entry point another project calls at startup: it ships the profile it
wants as text, asks for it to be placed, and if it had to write one,
tells its user to run `srcert` against that name.

THE TWO COPIES HAVE DIFFERENT RULES ON PURPOSE. The live profile is
written only when absent, because the user is meant to customise it and
an install must never overwrite that. The reference copy is rewritten
every time, because its whole job is to say what the application
CURRENTLY ships - a stale reference is worse than none, since it is what
a customised profile gets diffed against. Nothing reads the reference, so
refreshing it cannot break a deployment.

The text is PARSED before either write, so a caller cannot install a
profile that `srcert` will then refuse to read. That also means a
consumer embedding its profile at compile time gets the schema checked at
its own first start rather than at certificate generation.

## fn validate_snake

A profile name decides a filename, so it is a plain snake or nothing. It
is refused rather than sanitised for the reason recorded against
`InvalidProfileName`: a cleaned name silently addresses a different
profile.
