# Curating Your Audit Set

Each entry in your `audits.toml` represents your organization's seal of
approval. What that means is ultimately up to you, but you should be mindful of
the trust that others may be placing in you and the consequences for your brand
if that trust is broken.

This section outlines some norms and best-practices for responsible
participation in the cargo-vet ecosystem.

## Oversight and Enforcement

The most essential step is to ensure that you have adequate access controls on
your `supply-chain` directory (specifically `audits.toml`). For small projects
where a handful of maintainers review every change, the repository's ordinary
controls may be sufficient. But as the set of maintainers grows, there is an
increasing risk that someone unfamiliar with the significance of `audits.toml`
will approve an audit without appropriate scrutiny.

For projects where more than five individuals can approve changes, we recommend
designating a small group of individuals to oversee the audit set and ensure
that all submissions meet the organization's standards
([example](https://groups.google.com/a/mozilla.org/g/governance/c/wMWBqkCnR34)).
GitHub-hosted projects can use the
[CODEOWNERS](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
file to ensure that all submissions are approved by a member of that group.

## Evaluating Submissions

When someone submits an audit, there is no real way to check their work. So
while code submissions from anonymous contributors can often be quite valuable,
audits need to come from a known individual who you trust to represent your
organization. Such a person should have the technical proficiency to reliably
identify problems, the professionalism to do a good job, and the integrity to be
truthful about their findings.

A good litmus test is whether you would permit this individual to single-handedly
review and accept a patch from an anonymous contributor. The simplest approach
is just to restrict audit submissions to that set of people. However, there may
be situations where you find it reasonable to widen the set — such as former
maintainers who depart on good terms, or individuals at other organizations with
whom you have extensive relationships and wouldn't hesitate to bring on board if
the opportunity arose.

## Self-Certification

A natural consequence of the above is that there is no general prohibition
against organizations certifying crates that they themselves published. The
purpose of auditing is to extend an organization's seal of approval to code they
didn't write. The purpose is not to add additional layers of review to code that
they did write, which carries that seal by default.

Self-certified crates should meet an organization's own standards for first-party
code, which generally involves every line having undergone proper code review.
This "second set of eyes" principle is important, it's just not one that
cargo-vet can mechanically enforce in this context. In the future, cargo-vet may
add support for requiring that crates have been audited by N organizations,
which would provide stronger guarantees about independent review.
