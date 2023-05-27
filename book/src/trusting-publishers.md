## Trusting Publishers

In addition to audits, `cargo vet` also supports trusting releases of a given
crate by a specific publisher.

### Motivation

The core purpose of `cargo vet` is to assign trust to the contents of each crate
you use. The tool is audit-oriented because the crates in the ecosystem are very
heterogeneous in origin: it's usually impractical to require that every
dependency was _developed_ by a trusted source, so the next best thing is to
ensure that everything has been _audited_ by a trusted source.

However, there are cases where you do trust the developer.  Rather than
requiring an additional audit record for these crates, `cargo vet` allows you to
declare that you trust the developer of a given crate to always release code
which meets the desired criteria.

### Mechanics

Trusted publishers may be added with `cargo vet trust`. Entries require a trust
expiration date, which ensures that the judgment is revisited periodically.

The trust relationships are recorded in the `trusted` section of `audits.toml`:
```
[[trusted.baz]]
criteria = "safe-to-deploy"
user-id = 5555 // Alice Jones
start = ...
end = ...
notes = "Alice is an excellent developer and super-trustworthy."
```

### Suggestions

When there is an existing trust entry for a given publisher in your audit set or
that of your imports, `cargo vet suggest` will suggest that you consider adding
trust entries for a new unaudited crate by the same publisher:

```
$ cargo vet suggest
  recommended audits for safe-to-deploy:
      cargo vet inspect baz 1.3   (used by mycrate)  (2033 lines)
        NOTE: mozilla trusts Alice Jones (ajones) - consider cargo vet trust baz or cargo vet trust --all ajones
```

Trust entries are fundamentally a heuristic. The trusted publisher is not
consulted and may or may not have personally authored or reviewed all the code.
Thus it is important to assess the risk and potentially do some investigation on
the development and release process before trusting a crate.

