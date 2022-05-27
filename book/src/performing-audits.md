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
      bar:1.5 missing ["safe-to-deploy"]
      baz:1.3 missing ["safe-to-deploy"]
      foo:1.2.1 missing ["safe-to-deploy"]

  recommended audits for safe-to-deploy:
      cargo vet diff foo 1.2 1.2.1  (10 lines)
      cargo vet diff bar 2.1.1 1.5  (253 lines)
      cargo vet inspect baz 1.3     (2033 lines)

  estimated audit backlog: 2296 lines

  Use |cargo vet certify| to record the audits.
```

Note that if other versions of a given crate have already been verified, there
will be multiple ways to perform the review: either from scratch, or relative to
one or more already-audited versions. In these cases, `cargo vet`
computes all the possible approaches and selects the smallest one.

You can, of course, choose to add one or more unvetted dependencies to the
`unaudited` list instead of auditing them. This may be expedient in some
situations, though doing so frequently undermines the value provided by the
tool.

## Inspecting Crates

Once you've identified the audit you wish to perform, the next step is to
produce the artifacts for inspection. This is less trivial than it might sound:
even if the project is hosted somewhere like GitHub, there's no guarantee that
the code in the repository matches the bits submitted to crates.io. And the
packages on crates.io aren't easy to download manually.

To make this easy, the `cargo vet inspect` subcommand will ensure the crate has
been downloaded to your local registry cache and drop your terminal into the
appropriate directory to inspect it with whatever tools you like. When you
finish the audit, you can use `cargo vet certify` to add the entry to
`audits.toml`:

```
$ cargo vet inspect baz 1.3
  Opening nested shell in ~/.cargo/registry/src/github.com-1ecc6299db9ec823/baz-1.3
  Use `exit` or Ctrl-D to finish.
$ ...
$ exit
$ cargo vet certify baz 1.3

  I, Alice, certify that I have audited version 1.3 of baz in accordance with
  the following criteria:

  ...

 (type "yes" to certify): yes

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
  1.2.1 of baz in accordance with the following criteria:

  ...

  (type "yes" to certify): yes

  Recorded relative audit between foo versions 1.2 and 1.2.1
```

In the future, it may be valuable to stand up a web service to provide a richer
display of the differences between public crates. However, since auditing is
usually a much lighter-weight process than full code review, this functionality
is not essential.

## Shrinking the `unaudited` Table

Even when your project is passing `cargo vet`, lingering entries in `unaudited`
could still leave you vulnerable. As such, shrinking it is a worthwhile endeavor.

Any malicious crate can compromise your program, but not every crate requires
the same amount of effort to verify. Some crates are larger than others, and
different versions of the same crate are usually quite similar. To take
advantage of this, `cargo vet suggest` can estimate the lowest-effort audits
you can perform to reduce the number of entries in `unaudited`, and
consequently, your attack surface.

More precisely, `cargo vet suggest` computes the number of lines that would need
to be reviewed for each unaudited dependency, and displays them in order. This
is the same information you'd get if you emptied out `unaudited` and re-ran
`cargo vet`.

## Suggestions from the Registry

When `cargo vet` suggests audits — either after a failed vet or during `cargo
vet suggest` — it also fetches the contents of the
[registry](importing-audits.md#the-registry) and checks whether any of the
available sets contain audits which would fill some or all of the gap. If so, it
enumerates them so that the developer can consider importing them in lieu of
performing the entire audit themselves:

```
$ cargo vet suggest
  recommended audits for safe-to-deploy:
      cargo vet inspect baz 1.3  (2033 lines)
        Note: "firefox" contains an audit for baz 1.2, consider importing it.

  estimated audit backlog: 2033 lines

  Use |cargo vet certify| to record the audits.
```
