# How Vetting Works

This section provides additional detail on the mechanics of `cargo vet`.

## Scope

When vetting dependencies, `cargo vet` will execute the `cargo
metadata` subcommand to learn about the crate graph. All dependencies can be
categorized as:

* Path dependencies - these dependencies are ignored. The source code is
  typically in the repository and already subject to normal review policies.

* Git dependencies - these dependencies are ignored. It is expected that git
  dependencies have a manual verification process if necessary, or it's
  otherwise expected that these are typically private git repositories anyway.

* Non-crates.io registry dependencies - these dependencies are ignored. It's
  expected that a non-default registry is likely private or has its own review
  and/or publication policies. The tool may eventually support
  this if there are large public non-crates.io mirrors, but at this time they
  aren't verified.

* Crates.io dependencies - these are verified, as specified below.

Or, in other words, while Cargo allows pulling crates in from many locations
only those from crates.io are currently verified by `cargo trust`. Note though
that every single dependency in `cargo metadata` (and transitively `Cargo.lock`)
from crates.io will be verified to be trusted. It's important to note that not
all builds will use all these crates. For example:

* `dev-dependencies` are only used during testing
* Optional dependencies may be disabled
* Platform-specific dependencies may not be built if you're not building on
  that platform.

Despite this all dependencies must be allowed by the trust store. The
rationale for this is that it's a conservative choice because all of these
dependencies may be used at one point, and it's not certain when they might
be used in typical build processes.

For more information about this, and known deficiencies, see the documentation
on [platform specific dependencies](./platform-specific.md).

## Algorithm

The following is a simplified sketch of what happens when `cargo vet`
is invoked.

First, the project's [configuration](./config.md) is be parsed and loaded.

If not running in locked mode:
* Each of the URLs listed in the `audits` key of `trusted.toml` is then
fetched. These files are then merged and stored in `trusted.lock`.
* Crates.io is queried to retrieve the owners of each entry in the `crates`
key of `trusted.toml`. If there is no corresponding entry in `owners.lock`,
one is added. If there is an existing entry and the entry differs from the
response received from crates.io, an error is thrown.


`audit.toml`, `trusted.lock`, and  `unaudited.toml` are then parsed. If any of the
three are not well-formed, an error is thrown.

Next, the files are ingested in order into a table, indexed by crate name. Each table
entry contains a list of absolute versions, a list of version deltas, a list of forbidden versions, and a boolean
indicating whether the crate appeared in the `crates` list in `trusted.toml`. Each insertion checks
for overlap between the set of audited versions and forbidden versions; if overlap is created, an error is thrown.

The list of crates to be verified is then enumerated. For each such crates, the following steps are performed:

* The crate name is looked up in the table. If there is no entry, verification fails.

* If the boolean is set to True, verification succeeds.

* If the crate version matches the list of forbidden versions, verification fails.

* If the crate version matches the list of absolute versions, verification succeeds.

* All delta entries whose right-hand-side matches the crate version are collected. For
each such entry, the verification algorithm is recursively run with the version specified
on the left-hand-side (with appropriate loop checking). If any recursive call suceeds,
verification succeeds.

* Otherwise, verification fails.

If verification fails, an error is generated, along with a list of any versions of the
same crate that would have passed verification. These can be used as inputs to `cargo vet diff`.

If any entries in `unaudited.toml` are superfluous — i.e. verification would succed without them — a
warning is generated so that the list can be pared down.
