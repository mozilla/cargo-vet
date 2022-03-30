# Design Choice FAQ

This section serves to document the rationale behind various design choices and
highlight some alternatives considered. This should be considered supplementary
to the [Rationale & Design](./rationale.md) section.

## What about crates where I trust the author?

You might find yourself using a crate authored either by someone you personally
know or by a well-known member the community, in which case you might see low
value in an additional audit. In this situation, you are of course free to
simply leave the crate in the `unaudited` list indefinitely, perhaps with a
note indicating that this specific audit is a low priority.

There are, of course, dangers in being too permissive in these cases. Crates are
often a collaborative effort, and it may not be the case that this trusted
individual personally reviewed every contribution to date and will continue to do
so forever. If the author meets the criteria specified in your `Policy.md` for
certifying audits, a better approach is to have them contribue the audit
directly to your `audits.toml`.


## Why does `cargo vet init` automatically exempt all existing dependencies?

A key goal of `cargo vet` is to make it very easy to go from first learning
about the tool to having it running on CI. Having an open-ended task — like
auditing one or more crates — on that critical path increases the chance that
the developer gets side-tracked and never completes the setup. So the idea is to
enable developers to quickly get to a green state, and then use `cargo vet
suggest` to ratchet down the set of unaudited code at their own pace.


## Why is there no helper for recording forbidding crates?

One could imagine pairing `cargo vet certify` with a corresponding `cargo vet
forbid` to record `!` entries in `audits.toml`. This isn't supported for three
reasons:
* Security problems are rarely isolated to an exact version, which means you
  will generally want to specify a range of versions. In order to be
  self-explanatory, the syntax for this in `audits.toml` involves a combination
  of  `*`, `(`, `)`, `[`, and `]`. All of these are shell-parsed, and so passing
  them to a helper would either require cumbersome escaping, or the complexity
  of an alternative shell-friendly syntax.
* The situation in which you need to forbid a dependency is not likely to arise
  frequently.
* When the situation does arise, the effort required to manually update
  `audits.toml` is dwarfed by the effort of actually extricating the dependency
  from your project.
