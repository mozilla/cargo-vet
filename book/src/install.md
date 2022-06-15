# Installation

> **Note**: Since `cargo vet` is under rapid development, we have intentionally
> left the crates.io package as a placeholder to signal that it is not quite
> ready for general use. Firefox developers can access the tool by invoking
> `./mach cargo vet`, and anyone eager to try it out is welcome to pull the
> repository and invoke `cargo install --path .` Bug reports welcome!
>
> We aim to publish a proper release in the coming weeks, and appreciate your
> patience. Once we do, the following instructions will become the canonical way
> to install `cargo vet`.

Installing `cargo vet` can be done through Cargo:

```
$ cargo install cargo-vet
```

Afterwards you can confirm that it's installed via:

```
$ cargo vet --version
```
