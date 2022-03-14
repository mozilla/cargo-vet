# Platform-specific Dependencies

One of the known deficiencies in `cargo vet` is that it doesn't handle
platform specific dependencies well in all cases. Some trust stores, for
example, might be for projects that are only built on Linux, but are never
built on Windows. Often though they'll depend on crates which have a
Windows-specific dependency on the `winapi` crate, and `cargo vet` will
currently require that `winapi` be vetted, even though for
this project it's never built.

This is generally a problem with Cargo itself, where `Cargo.lock` lists all
packages for all platforms, irrespective of whether the top-level project is
ever built for that platform.

The easiest way to address this is to add the platform-specific crates to
`unaudited.toml`. To facilitate this use-case, `unaudited.toml` allows
dependency versions to be star-matched like so:

```
foo = [
  "1.*"
]
```

Which allows you to avoid constantly fiddling with the version numbers of crates
you've confirmed are not actually built for your project. The downside of this
approach, of course, is that your dependency graph might change in the future
such that these crates are in fact built. For that reason, the more conservative
approach is to audit these crates like any other.
