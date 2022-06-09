# Design Choice FAQ

This section serves to document the rationale behind various design choices and
highlight some alternatives considered. This should be considered supplementary
to the [Rationale & Design](./rationale.md) section.

## What about crates where I trust the author?

You might find yourself using a crate authored either by someone you personally
know or by a well-known member the community, in which case you might see low
value in an additional audit. In this situation, you are of course free to
simply leave the crate in the `unaudited` list indefinitely, perhaps with a
`suggest = false` and note indicating that this specific audit is a low priority.

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


## Why does `cargo vet` require audits for overridden dependencies?

Cargo supports [dependency
overrides](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html),
which allows developers to replace public crates in their dependency graph with
a custom version. Strictly speaking, these overrides are first-party code, but
`cargo vet` nevertheless requires a corresponding audit for the public version.

The reason is that this custom version might be generated in one of two ways: by
building a semantically-compatible replacement from scratch, or by starting with
the source of the original crate and making some (potentially-minimal)
modifications. The latter case is quite common, and in practice rarely entails a
full audit of the original crate despite formally transforming it into
first-party code.  Since `cargo vet` has no way to distinguish this case from a
from-scratch rewrite, it conservatively assumes the override is a derivative
work, and requires the original version to be audited. The from-scratch can be
handled by adding an entry to the `unaudited` table with `suggest = false` and a
note explaining the situation.

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
