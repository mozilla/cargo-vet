# Performing Audits

Human attention is a precious resource, so `cargo vet` provides several features
to spend that attention as efficiently as possible.

## Managing Dependency Changes

When you run `cargo update`, you generally pull in new crates or new versions of
existing crates, which may cause `cargo vet` to fail. In this situation,
`cargo vet` identifies the relevant crates and recommends how to audit them:

```
$ cargo update
  ....

$ cargo vet
  Vetting Failed!

  3 unvetted dependencies:
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
`exemptions` list instead of auditing them. This may be expedient in some
situations, though doing so frequently undermines the value provided by the
tool.

## Inspecting Crates

Once you've identified the audit you wish to perform, the next step is to
produce the artifacts for inspection. This is less trivial than it might sound:
even if the project is hosted somewhere like GitHub, there's no guarantee that
the code in the repository matches the bits submitted to crates.io. And the
packages on crates.io aren't easy to download manually.

To make this easy, the `cargo vet inspect` subcommand will give you a link to
the exact version of the crate hosted on [Sourcegraph](https://about.sourcegraph.com/).

When you finish the audit, you can use `cargo vet certify` to add the entry to
`audits.toml`:

```
$ cargo vet inspect baz 1.3
You are about to inspect version 1.3 of 'baz', likely to certify it for "safe-to-deploy", which means:

   ...

You can inspect the crate here: https://sourcegraph.com/crates/baz@v1.3

(press ENTER to open in your browser, or re-run with --mode=local)

$ cargo vet certify baz 1.3

  I, Alice, certify that I have audited version 1.3 of baz in accordance with
  the following criteria:

  ...

 (type "yes" to certify): yes

  Recorded full audit of baz version 1.3
```

You can also use the `--mode=local` flag to have `inspect` download the crate
source code and drop you into a nested shell to inspect it.

Similarly, `cargo vet diff` will give you a [Sourcegraph](https://about.sourcegraph.com/)
link that will display the diff between the two versions.

```
$ cargo vet diff foo 1.2 1.2.1

You are about to diff versions 1.2 and 1.2.1 of 'foo', likely to certify it for "safe-to-deploy", which means:

   ...

You can inspect the diff here: https://sourcegraph.com/crates/foo/-/compare/v1.2...v1.2.1

$ cargo vet certify foo 1.2 1.2.1

  I, Alice, certify that I have audited the changes between versions 1.2 and
  1.2.1 of baz in accordance with the following criteria:

  ...

  (type "yes" to certify): yes

  Recorded relative audit between foo versions 1.2 and 1.2.1
```

You can also use `--mode=local` flag to have `diff` download the two crates and display a
git-compatible diff between the two.

## Shrinking the `exemptions` Table

Even when your project is passing `cargo vet`, lingering entries in `exemptions`
could still leave you vulnerable. As such, shrinking it is a worthwhile endeavor.

Any malicious crate can compromise your program, but not every crate requires
the same amount of effort to verify. Some crates are larger than others, and
different versions of the same crate are usually quite similar. To take
advantage of this, `cargo vet suggest` can estimate the lowest-effort audits
you can perform to reduce the number of entries in `exemptions`, and
consequently, your attack surface.

More precisely, `cargo vet suggest` computes the number of lines that would need
to be reviewed for each exemptions dependency, and displays them in order. This
is the same information you'd get if you emptied out `exemptions` and re-ran
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
      cargo vet inspect baz 1.3   (used by mycrate)  (2033 lines)
        NOTE: cargo vet import mozilla would reduce this to a 17-line diff
      cargo vet inspect quxx 2.0  (used by baz)      (1000 lines)
        NOTE: cargo vet import mozilla would eliminate this

  estimated audit backlog: 3033 lines

  Use |cargo vet certify| to record the audits.
```

## Trusting Authors of Crates

`cargo vet` achieves supply-chain integrity by ensuring that the contents of each crate you depend
on are signed-off by a trusted source. However, sometimes it's the case that one or more crates you
depend on are _developed_ by a trusted source. Rather than requiring an additional audit of these
crates, or encouraging a false audit that says "we trust this developer" (as that isn't really an
audit of the code), `cargo vet` allows you to declare that you trust a developer to satisfactorily
audit code which they have published.

This is particularly useful as a means of self-certification, where members or groups in your
organization have published crates separately from your project, but you consider them trustworthy
auditors of their own code.

Trusted publishers may be added with `cargo vet trust`. This allows you to either trust all crates
solely published by a specific author (`cargo vet trust --all USER`), the sole publisher of a
specific crate (`cargo vet trust CRATE`), or a specific publisher of a crate when more than one
exists (`cargo vet trust CRATE USER`). Entries require a trust expiration date, which ensures that
the judgment is revisited periodically.

The trust relationships are recorded in the `trusted` section of `audits.toml`:
```
[[trusted.serde]]
criteria = "safe-to-deploy"
user-id = 3618 // David Tolnay
start = ...
end = ...
notes = "David is super-trustworthy."
```

When imported audits trust a publisher or you have existing trust entries for a publisher, `cargo
vet suggest` will suggest that you consider adding trust entries for a new unaudited crate by the
same publisher.

Note that unlike wildcard entries, which are an explicit promise that a publisher audits their
crates to meet the audit criteria, trust entries are a heuristic. The trusted publisher may or may
not have personally authored or reviewed all the code. Thus it is important to assess the risk and
potentially do some investigation before trusting an author.
