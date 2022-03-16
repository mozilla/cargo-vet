# Design Choice FAQ

This section serves to document the rationale behind various design choices and
highlight some alternatives considered. This should be considered supplementary
to the [Rationale & Design](./rationale.md) section.

## Why does `cargo vet init` automatically exempt all existing dependencies?

A key goal of `cargo vet` is to make it very easy to go from first learning
about the tool to having it running on CI. Having an open-ended task — like
auditing one or more crates — on that critical path increases the chance that
the developer gets side-tracked and never completes the setup. So the idea is to
enable developers to quickly get to a green state, and then use `cargo vet
suggest` to ratchet down the set of unaudited code at their own pace.


## Why is there no helper for recording forbidding crates?

One could imagine pairing `cargo vet certify` with a corresponding `cargo vet
forbid` to record `!` entries in `audited.toml`. This isn't supported for three
reasons:
* Security problems are rarely isolated to an exact version, which means you
  will generally want to specify a range of versions. In order to be
  self-explanatory, the syntax for this in `audited.toml` involves a combination
  of  `*`, `(`, `)`, `[`, and `]`. All of these are shell-parsed, and so passing
  them to a helper would either require cumbersome escaping, or the complexity
  of an alternative shell-friendly syntax.
* The situation in which you need to forbid a dependency is not likely to arise
  frequently.
* When the situation does arise, the effort required to manually update
  `audited.toml` is dwarfed by the effort of actually extricating the dependency
  from your project.
