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
individual personally reviewed every contribution to date and will continue to
do so forever. If the author has the authority to certify audits for your
project, a better approach is to have them contribue the audit directly to your
`audits.toml`.


## Why does `cargo vet init` automatically exempt all existing dependencies?

A key goal of `cargo vet` is to make it very easy to go from first learning
about the tool to having it running on CI. Having an open-ended task — like
auditing one or more crates — on that critical path increases the chance that
the developer gets side-tracked and never completes the setup. So the idea is to
enable developers to quickly get to a green state, and then use `cargo vet
suggest` to ratchet down the set of unaudited code at their own pace.


## Why is there no helper for recording violation entries?

One could imagine pairing `cargo vet certify` with a corresponding `cargo vet
record-violation`. This isn't supported for three reasons:
* Security problems are rarely isolated to an exact version, which is why
  `violation` [supports](audit-entries.md#violation) range syntax. Some elements
  of this syntax (like `*', `<` and `>`) are shell-parsed, and so passing
  them to a helper would either require cumbersome escaping, or the complexity
  of an alternative shell-friendly syntax.
* The situation in which you need to record a violation is not likely to arise
  frequently.
* When the situation does arise, the effort required to manually update
  `audits.toml` is dwarfed by the effort of actually extricating the dependency
  from your project.

## How does this relate to `cargo crev`?

This work was partially inspired by `cargo crev`, and borrows some aspects
from its design. We are grateful for its existence and the hard work behind it.
`cargo vet` makes a few design choices that differ from `cargo crev`:
* **Project-Oriented:** `cargo vet` is geared towards usage by organizations,
  and therefore does not separate audits by individual developer. Consequently,
  it does not have a separate identity and authentication layer.
* **No Web-of-Trust:** there is no notion of transitive trust. The decision to
  trust audits performed by another party is independent of that party's trust
  choices, which might be rooted in a different threat model.
* **Automated Enforcement:** `cargo vet` is designed to be run as an enforcement
  tool for projects to manage (rather than just inspect) their supply chains,
  and consequently has a number of affordances in this direction.
* **Audit Criteria:** `cargo vet` supports recording
  [multiple kinds of audits](audit-criteria.md).

Eventually, it could make sense to implement some form of bridging between the
two systems.
