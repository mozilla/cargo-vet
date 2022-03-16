# Specifying Trust

The fastest way to shrink `unaudited.toml` is to encode information about who
you trust in `trusted.toml`. There are two mechanisms for this.

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
