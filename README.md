# cargo-vet

[![crates.io](https://img.shields.io/crates/v/cargo-vet.svg)](https://crates.io/crates/cargo-vet)
[![docs.rs](https://docs.rs/cargo-vet/badge.svg)](https://docs.rs/cargo-vet)
![Rust CI](https://github.com/bholley/cargo-vet/workflows/Rust%20CI/badge.svg?branch=master)

cargo-vet helps you vet your dependencies and rely on the vetting done by other projects.



# Current Default Directory Structure

(As implemented by the CLI, currently divergent from the book.)

* supply-chain/
  * audited.toml
  * trusted.toml
  * untrusted.toml





# cargo-vet CLI manual

> This manual can be regenerated with `cargo vet help-markdown`

Version: `cargo-vet 0.1.0`

Supply-chain security for Rust

# USAGE
cargo-vet [OPTIONS] [SUBCOMMAND]

# OPTIONS
### `--all-features`
Activate all available features

### `--exclude <SPEC>`
Exclude packages from being processed

### `--features <FEATURES>`
Space-separated list of features to activate

### `-h, --help`
Print help information

### `--locked`
Do not pull in new "audits"

### `--log-file <LOG_FILE>`
Instead of stderr, write logs to this file (only used after successful CLI parsing)

### `--manifest-path <PATH>`
Path to Cargo.toml

### `--no-default-features`
Do not activate the `default` feature

### `--output-file <OUTPUT_FILE>`
Instead of stdout, write output to this file

### `-p, --package <SPEC>`
Package to process (see `cargo help pkgid`)

### `-v, --verbose <VERBOSE>`
How verbose logging should be (log level)

\[default: warn]
\[possible values: off, error, warn, info, debug, trace]

### `-V, --version`
Print version information

### `--workspace`
Process all packages in the workspace

# SUBCOMMANDS

## `audits`
??? List audits mechanisms ???

## `certify`
Mark `$crate $version` as reviewed with `$message`

## `diff`
Yield a diff against the last reviewed version

## `fetch`
Fetch the source of `$crate $version`

## `forbid`
Mark `$crate $version` as unacceptable with `$message`

## `help`
Print this message or the help of the given subcommand(s)

## `help-markdown`
Print --help as markdown (for generating docs)

## `init`
initialize cargo-vet for your project

## `suggest`
Suggest some low-hanging fruit to review



