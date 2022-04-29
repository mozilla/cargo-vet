# cargo-vet

[![crates.io](https://img.shields.io/crates/v/cargo-vet.svg)](https://crates.io/crates/cargo-vet)
![Rust CI](https://github.com/bholley/cargo-vet/workflows/Rust%20CI/badge.svg?branch=main)

The `cargo vet` subcommand is a tool to help projects ensure that third-party Rust dependencies have been audited by a trusted source. It strives to be lightweight and easy to integrate.

More details available in the [book](https://bholley.net/cargo-vet/).

# cargo vet CLI manual

> This manual can be regenerated with `cargo vet help-markdown`

Version: `cargo-vet 0.1.0`

Supply-chain security for Rust

### USAGE
cargo vet [OPTIONS] [SUBCOMMAND]

### OPTIONS
#### `--all-features`
Activate all available features

#### `--exclude <SPEC>`
Exclude packages from being processed

#### `--features <FEATURES>`
Space-separated list of features to activate

#### `-h, --help`
Print help information

#### `--locked`
Do not pull in new "audits"

#### `--log-file <LOG_FILE>`
Instead of stderr, write logs to this file (only used after successful CLI parsing)

#### `--manifest-path <PATH>`
Path to Cargo.toml

#### `--no-default-features`
Do not activate the `default` feature

#### `--output-file <OUTPUT_FILE>`
Instead of stdout, write output to this file

#### `-p, --package <SPEC>`
Package to process (see `cargo help pkgid`)

#### `-V, --version`
Print version information

#### `--verbose <VERBOSE>`
How verbose logging should be (log level)

\[default: warn]  
\[possible values: off, error, warn, info, debug, trace]  

#### `--workspace`
Process all packages in the workspace

### SUBCOMMANDS
* [accept-criteria-change](#cargo-vet-accept-criteria-change): Accept changes that a foreign audits.toml made to their criteria
* [certify](#cargo-vet-certify): Mark `$package $version` as reviewed with `$message`
* [diff](#cargo-vet-diff): Yield a diff against the last reviewed version
* [fmt](#cargo-vet-fmt): Reformat all of vet's files (in case you hand-edited them)
* [help](#cargo-vet-help): Print this message or the help of the given subcommand(s)
* [init](#cargo-vet-init): initialize cargo-vet for your project
* [inspect](#cargo-vet-inspect): Fetch the source of `$package $version`
* [suggest](#cargo-vet-suggest): Suggest some low-hanging fruit to review

<br><br><br>
## cargo vet help 
Print this message or the help of the given subcommand(s)

### cargo vet help USAGE
```
cargo vet help [SUBCOMMAND]...
```

### cargo vet help ARGS
#### `<SUBCOMMAND>...`
The subcommand whose help message to display

<br><br><br>
## cargo vet help-markdown 
Print --help as markdown (for generating docs)

### cargo vet help-markdown USAGE
```
cargo vet help-markdown
```

### cargo vet help-markdown OPTIONS
#### `-h, --help`
Print help information

<br><br><br>
## cargo vet fmt 
Reformat all of vet's files (in case you hand-edited them)

### cargo vet fmt USAGE
```
cargo vet fmt
```

### cargo vet fmt OPTIONS
#### `-h, --help`
Print help information

<br><br><br>
## cargo vet suggest 
Suggest some low-hanging fruit to review

### cargo vet suggest USAGE
```
cargo vet suggest [OPTIONS]
```

### cargo vet suggest OPTIONS
#### `--guess-deeper`
Try to suggest even deeper down the dependency tree (approximate guessing).

By default, if a dependency doesn't have sufficient audits for *itself* then we won't
try to speculate on anything about its dependencies, because we lack sufficient
information to say for certain what is required of those dependencies. This overrides
that by making us assume the dependencies all need the same criteria as the parent.

#### `-h, --help`
Print help information

<br><br><br>
## cargo vet certify 
Mark `$package $version` as reviewed with `$message`

### cargo vet certify USAGE
```
cargo vet certify <PACKAGE> <VERSION1> [VERSION2]
```

### cargo vet certify ARGS
#### `<PACKAGE>`


#### `<VERSION1>`


#### `<VERSION2>`


### cargo vet certify OPTIONS
#### `-h, --help`
Print help information

<br><br><br>
## cargo vet diff 
Yield a diff against the last reviewed version

### cargo vet diff USAGE
```
cargo vet diff <PACKAGE> <VERSION1> <VERSION2>
```

### cargo vet diff ARGS
#### `<PACKAGE>`


#### `<VERSION1>`


#### `<VERSION2>`


### cargo vet diff OPTIONS
#### `-h, --help`
Print help information

<br><br><br>
## cargo vet inspect 
Fetch the source of `$package $version`

### cargo vet inspect USAGE
```
cargo vet inspect <PACKAGE> <VERSION>
```

### cargo vet inspect ARGS
#### `<PACKAGE>`


#### `<VERSION>`


### cargo vet inspect OPTIONS
#### `-h, --help`
Print help information

<br><br><br>
## cargo vet accept-criteria-change 
Accept changes that a foreign audits.toml made to their criteria

### cargo vet accept-criteria-change USAGE
```
cargo vet accept-criteria-change
```

### cargo vet accept-criteria-change OPTIONS
#### `-h, --help`
Print help information

<br><br><br>
## cargo vet init 
initialize cargo-vet for your project

### cargo vet init USAGE
```
cargo vet init
```

### cargo vet init OPTIONS
#### `-h, --help`
Print help information


