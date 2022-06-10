# Cargo Vet

The `cargo vet` subcommand is a tool to help projects ensure that third-party
Rust dependencies have been audited by a trusted source. It strives to be
lightweight and easy to integrate.

When run, `cargo vet` matches all of a project's third-party dependencies
against a set of audits performed by the project authors or parties they trust. If
there are any gaps, the tool provides mechanical assistance in performing
and documenting the audit.

The primary reason that people do not ordinarily audit open-source dependencies
is that it is too much work. There are a few key ways that `cargo vet` aims to
reduce developer effort to a manageable level:

* **Sharing**: Public crates are often used by many projects. These projects can
share their findings with each other to avoid duplicating work.

* **Relative Audits**: Different versions of the same crate are often quite similar
to each other. Developers can inspect the difference between two versions, and record
that if the first version was vetted, the second can be considered vetted as well.

* **Deferred Audits**: It is not always practical to achieve full coverage.
Dependencies can be added to a list of exceptions which can be ratcheted down over time. This makes it trivial to introduce `cargo vet` to a new project
and guard against future vulnerabilities while vetting the pre-existing code
gradually as time permits.

> **Note**: `cargo vet` is under active development. If you're interested in
> deploying it, [get in touch](mailto:bholley@mozilla.com).

