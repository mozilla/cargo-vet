# Setup

Now that you've installed `cargo vet`, you're ready to set it up for your project. Move
into the top-level project directory and execute the following:

```
$ cargo vet
  error: cargo vet is not configured
```

To be useful, `cargo vet` needs to know which audits have been performed and
what policy should be enforced. By default, this information is stored next to
`Cargo.lock` in a directory called `supply-chain`. This location is
[configurable](./config.md).

To get started, you can invoke:

```
$ cargo vet init
```

This creates and populates the `supply-chain` directory. It contains two files:
`audits.toml` and `config.toml`. The `unaudited` table of `config.toml` is
populated with the full list of third-party crates currently used by the
project. The files in this directory should be added to version control along
with `Cargo.lock`.

Now, try vetting again:

```
$ cargo vet
  Vetting Succeeded (0 audited, X unaudited)
```

You're now up and running, though with an empty audit set: vetting only succeeds
because your list of exceptions contains the exact set of current dependencies
used in your project. Generally speaking, you should try to avoid more
exceptions, and ideally seek to shrink the list over time.
