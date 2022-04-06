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

If not running in locked mode, each of the URLs listed in the `imports` key of
`config.toml` is then fetched. These files are then processed and the resulting
data is stored in `imports.lock`. The descriptions for any mapped criteria are
stored as well, and any changes to previously-recorded descriptions will cause
`cargo vet` to fail and require `cargo vet accept-criteria-change` to be run.
Any unmapped criteria (and audits under those criteria) are discarded.

`audits.toml`, `imports.lock`, and  `config.toml` are then parsed. If any of the
three are not well-formed, an error is thrown.

Next, the files are ingested in order into a multi-level table, indexed first by
crate name and then by criteria. Each concrete entry contains a list of absolute
versions, a list of version deltas, a list of violation versions. Each insertion
checks for overlap between the set of audited versions and violation versions;
if overlap is created, an error is thrown.

Next, the depedency subtrees of each top-level crate are traversed in accordance
with the policy specified for each crate. TODO: Precisely specify the subtree
traversal algorithm.

If verification fails, an error is generated, along with a list of any versions
of the same crate that would have passed verification. These can be used as
inputs to `cargo vet diff`.

If any entries in `unaudited` are superfluous — i.e. verification would succeed
without them — a warning is generated so that the list can be pared down.
