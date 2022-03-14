# Specifying Trust

The fastest way to shrink `unaudited.toml` is to encode information about who
you trust in `trusted.toml`. There are two mechanisms for this.

## The `crates` directive

This directive allows you to specify that you have enough trust in a crate's
release process (and the change process for that release process) that you
consider any version of that crate safe without audit.

For example, you could write:
```
crates = [
  "atomic_refcell",
  "rayon",
]
```

A potential pitfall is for ownership of a crate to change hands from an original
trusted party to someone else. To guard against this, `cargo vet` records the
current crates.io owner(s) in `owners.lock`. If ownership changes, `cargo vet`
will fail until the lock file is manually updated to reflect current ownership.

While this provides some protection, it is not fool-proof. The original owner may
not be as trustworthy as you believed, or the crates.io owners may choose to release
changes that they did not personally author or review. Library authors are encouraged to
keep crates.io ownership synchronized with repository commit access, and document
their code review and release policies to assist others in assessing risk.

## The `audits` directive

This directive allows you to virtually merge audit lists from other
projects into your own. This may or may not be a reciprocal relationship,
since it's fine to import audits from another party with a stricter audit policy,
but not the other way around.

For example:
```
audits = [
  "https://raw.githubusercontent.com/rust-lang/cargo-trust-store/audited.toml",
  "https://hg.example.org/example/raw-file/tip/audited.toml"
]
```

Upon invocation, `cargo vet` will fetch these audit files, merge them, and store the result
in `trusted.lock`. Similar to `cargo vendor`, passing `--locked` will skip the fetch.

Note that there is intentionally no way to import an external `trusted.toml`. This
keeps trust relationships direct and easy to reason about. That said, you can always
inspect the `trusted.toml` of other projects for inspiration, and explicitly adopt
any entries that meet your requirements.
