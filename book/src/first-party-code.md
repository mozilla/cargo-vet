# First-Party Code

When run, `cargo vet` invokes the `cargo metadata` subcommand to learn about the
crate graph. When traversing the graph, `cargo vet` enforces audits for all
crates.io dependencies.

Generally speaking, all other nodes in the graph are considered trusted and
therefore non-auditable. This includes root crates, path dependencies, git
dependencies, and custom (non-crates.io) registry dependencies.

However, there are some situations which blur the line between first- and
third-party code. This can occur, for example, when the `[patch]` table is used
to replace the contents of a crates.io package with a locally-modified version.
Sometimes the replacement is rewritten from scratch, but often it's derived from
the original, sometimes just with a single modification. Insofar as the package
you're using is still primarily third-party code, you'll want to audit it like
anything else — but cargo-vet has no foolproof way to mechanically deduce whether
the replacement is a derived work.

To ensure the right thing happens, cargo-vet detects these ambiguous situations
and requires the user to specify the intended behavior. Specifically, if there
exists a public crate with the same name and version as a given first-party
crate, cargo-vet will require a policy entry for that crate specifying
`audit-as-crates-io` as either true or false. If it's set to true, cargo-vet
will perform audit enforcement as if the crates.io version were being used.

It's important to note that any audits for such derived crates still correspond
to the crates.io version. This is what `inspect` and `certify` will display, and
this is what you should review before certifying, since others in the ecosystem
may rely on your audits when using the original crate without your particular
modifications.
