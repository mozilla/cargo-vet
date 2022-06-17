# Motivation

The discussion below covers the high-level motivation behind this approach. If
you're just interested in how it works, you can skip to the next section.

### Security Risks of Third-Party Code
Low-friction reuse of third-party components — via systems like crates.io or npm — is
an essential element of modern software development. Unfortunately, it also
widens the set of actors who can introduce a security vulnerability into the final
product.

These defects can be honest mistakes, or intentional supply-chain attacks. They
can exist in the initial version, or be introduced later as an update. They can
be introduced by the original author, or by a new maintainer
who acquires control over the release of subsequent versions.
Taken together, these avenues constitute a demonstrated and growing
risk to software security.

Ideally, the composition model would include technical guarantees to isolate
components from each other and prevent a defect in one component from compromising
the security of the entire program (e.g. [WebAssembly nanoprocesses](https://bytecodealliance.org/articles/announcing-the-bytecode-alliance)).
However, that is often not a realistic solution for many projects today. In the absence
of technical guarantees, the responsibility for ensuring software integrity falls to
humans. But reviewing every line of third-party code can be very time-consuming and
difficult, and undermines the original premise of low-friction code reuse. Practically
speaking, it usually just doesn't happen — even at large well-resourced companies.

### Tackling This in Rust
There are two properties of Rust that make this problem more tractable.

First, it's relatively easy to audit Rust code. Unlike C/C++, Rust code is
memory-safe by default, and unlike JavaScript, there is no highly-dynamic shared
global environment. This means that you can often reason at a high level about
the range of a module's potential behavior without carefully studying all of its
internal invariants. For example, a complicated string parser with a narrow
interface, no unsafe code, and no powerful imports has limited means to
compromise the rest of the program. This also makes it easier to conclude that a
new version is safe based on a diff from a prior trusted version.

Second, nearly everyone in the Rust ecosystem relies on the same set of basic tooling
— Cargo and crates.io — to import and manage third-party components, and there is high
overlap in the dependency sets. For example, at the time of writing,
[Firefox](https://hg.mozilla.org/mozilla-central/file/add572d6012047244d022436e0b5c578b3dd7cf7/Cargo.lock),
[wasmtime](https://github.com/bytecodealliance/wasmtime/blob/49c2b1e60a87623796046176500bed6afa956d2f/Cargo.lock),
and [the Rust compiler](https://github.com/rust-lang/rust/blob/532d3cda90b8a729cd982548649d32803d265052/Cargo.lock)
specified 406, 310, and 357 crates.io dependencies respectively[^1]. Ignoring
version, each project shares about half of its dependencies with at least one of
the other two projects, and 107 dependencies are common across all three.

This creates opportunities to share the analysis burden in an systematic way. If you're able to
discover that a trusted party has already audited the exact crate release you're using,
you can gain quite a bit of confidence in its integrity with no additional effort. If
that part has audited a different version, you could consider either switching to it, or
merely auditing the diff between the two. Not every organization
and project share the same level of risk tolerance, but there is a lot of common
ground, and substantial room for improvement beyond no sharing at all.

### Design

The core idea behind `cargo vet` is that teams perform these relatively-cheap
audits, document them in a structured way, and make that information available to
others. The more people that participate, the more likely each developer is to find
that a new import has already been audited, and the less total work there is for
everyone.

To remain lightweight, `cargo vet` does not introduce its own mechanisms for identity,
integrity, and history. Audits and trusted parties are recorded in a flat file in the project repository,
and are thus subject to the same access controls and record-keeping as the rest of the
project. No extra work is required to make an open-source projects audits available to
others, since others can simply reference the file directly from the public repository.
Closed-source projects, by contrast, will need to push a copy of their audit file to
a known public location if they wish to make it available to others.

The means of discovering other participants is expected to change over time as adoption grows. Early on,
parties can simply coordinate directly, and look to each other's lists of trusted sources
for inspiration. As the numbers grow, it may be helpful to develop a centralized directory.
Eventually, it may make sense to integrate this information directly with crates.io.

Audit sharing is a key force-multiplier behind `cargo vet`, but it is not essential.
You can of course decline to import any external audit sets, and either perform all the
audits yourself or add them to your allow-list and only audit updates. This second
approach can be a useful low-effort way to protect a mature projects from future
supply-chain attacks. By simply enforcing that any future imports are differentially
audited, you can reliably prevent future attacks while deferring verification against past
compromise (which may be a larger undertaking).

## Footnotes

[^1]: The following command string computes the names of the crates.io packages
  specified in `Cargo.lock`. Note the filtering for path and git dependencies,
  along with removing duplicates due to different versions of the same crate:

```
cat Cargo.lock | grep -e "name = " -e "source = \"registry" | awk '/source =/ { print prv_line; next } { prv_line = $0 }' | sort | uniq
```
