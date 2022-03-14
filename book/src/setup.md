# Setup

Now that you've installed `cargo vet`, you're ready to set it up for your project. Move
into the top-level project directory and execute the following:

```
$ cargo vet
  error: cargo vet is not configured
```

To start verifying crates you need to first need to specify the criteria to
vet against. By default, this information is stored next to `Cargo.lock` in a directory
called `supply-chain`. This location is [configurable](./config.md).

To get started, you can invoke:

```
$ cargo vet init
```

This creates and populates the `supply-chain` directory. It contains three files:
`audited.toml` (empty), `trusted.toml` (skeleton), and `unaudited.toml` (populated
with the full list of third-party crates currently used by the project). The files
in this directory should be added to version control along with `Cargo.lock`.

Now, try vetting again:

```
$ cargo vet
  All crates vetted!
```

You're now up and running, though with an empty audit set: vetting only succeeds
because `unaudited.toml` (your list of exceptions) contains the exact set of
current dependencies used in your project. Generally speaking, you should try to
avoid anything more to `unaudited.toml`, and ideally seek to shrink it over time.
