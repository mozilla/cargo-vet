# Configuration

By default, `cargo vet` data lives in a `supply-chain` directory next to `Cargo.lock`. This location is configurable via the `[package.metadata.vet]` directive in Cargo.toml, as well as via `[workspace.metadata.vet]` when using a workspace with a virtual root.

The default configuration is equivalent to the following:

```toml
[package.metadata.vet]
store = { path = './supply-chain' }
```
