# FAQ

This section aims to address a few frequently-asked questions whose answers
don't quite fit elsewhere in the book.


## Why does `cargo vet init` automatically exempt all existing dependencies?

A key goal of `cargo vet` is to make it very easy to go from first learning
about the tool to having it running on CI. Having an open-ended task — like
auditing one or more crates — on that critical path increases the chance that
the developer gets side-tracked and never completes the setup. So the idea is to
enable developers to quickly get to a green state, and then use `cargo vet
suggest` to ratchet down the set of exemptions at their own pace.


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
