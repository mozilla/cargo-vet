# Performing Audits

Human attention is a precious resource, so `cargo vet` provides several features
to spend that attention as efficiently as possibly.

## Managing Dependency Changes

When you run `cargo update`, you generally pull in new crates or new versions of
existing crates, which may cause `cargo vet` to fail. In this situation,
`cargo vet` identifies the relevant crates and recommends how to audit them:

```
$ cargo update
  ....

$ cargo vet
  Vetting Failed!

  3 unvetted depedencies:
    bar:1.5
    baz:1.3
    foo:1.2.1

  recommended audits:
    foo:1.2->1.2.1 (10 lines)
    bar:2.1.1->1.5 (253 lines)
    baz:1.3 (2033 lines)

  Use |cargo vet certify| to record the audits.
```

Note that if other versions of a given crate have already been verified, there
will be multiple ways to perform the review: either from scratch, or relative to
one or more already-audited versions. In these cases, `cargo vet`
computes all the possible approaches and selects the smallest one.

You can, of course, choose to add one or more unvetted dependencies to
`unaudited.toml` instead of auditing it. This may be expedient in some situations,
though doing so frequently undermines the value provided by the tool.

## Reviewing Crates

Once you've identified the audit you wish to perform, the next step is to
produce the artifacts for inspection. This is less trivial than it might sound:
even if the project is hosted somewhere like GitHub, there's no guarantee that
the code in the repository matches the bits submitted to crates.io. And the
packages on crates.io aren't easy to download manually.

To make this easy, the `cargo vet fetch` subcommand will download the relevant
crate to a temporary directory. When you finish the audit, you can use
`cargo vet certify` to add the entry to `audited.toml`:

```
$ cargo vet fetch baz 1.3
  Downloaded crate as /tmp/baz:1.3
$ ...
$ cargo vet certify baz 1.3

  I, Alice, certify that I have audited version 1.3 of baz in accordance with
  the criteria described in /path/to/Policy.md (type "yes" to certify): yes

  Recorded full audit of baz version 1.3
```

Similarly, `cargo vet diff` will fetch two versions of a given crate, compare
them, and output a git-compatible diff between the two:
```
$ cargo vet diff foo 1.2 1.2.1
  (Diff printed to stdout)
$ ...
$ cargo vet certify foo 1.2 1.2.1

  I, Alice, certify that I have audited the changes between versions 1.2 and
  1.2.1 of baz in accordance with the criteria described in /path/to/Policy.md
  (type "yes" to certify): yes

  Recorded relative audit between foo versions 1.2 and 1.2.1
```

In the future, it may be valuable to stand up a web service to provide
a richer display of the differences between public crates. However, since
auditing for security vulnerabilities is usually a much lighter-weight process
than full code review, this functionality is not essential.

## Shrinking `unaudited.toml`

Even when your project is passing `cargo vet`, lingering entries in `unaudited.toml`
could still leave you vulnerable. As such, shrinking it is a worthwhile endeavor.

Any malicious crate can compromise your program, but not every crate requires
the same amount of effort to verify. Some crates are larger than others, and
different versions of the same crate are usually quite similar. To take
advantage of this, `cargo vet suggest` can estimate the lowest-effort audits
you can perform to reduce the number of entries in `unaudited.toml`, and
consequently, your attack surface.

More precisely, `cargo vet suggest` computes the number of lines that would
need to be reviewed for each not-yet-audited dependency, and displays them
in order. This is the same information you'd get if you deleted `unaudited.toml`
and re-ran `cargo vet`:
```
$ cargo vet suggest
  3 audits to perform:
    foo:1.2->1.2.1 (10 lines)
    bar:1.3 (253 lines)
    baz:1.5 (5033 lines)
```

From there, you can use the `fetch`, `diff`, and `certify` subcommands to tackle
items on the list.

