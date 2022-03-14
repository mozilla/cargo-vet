# Configuring CI

As a final step in setting up a project, it's strongly recommended to
*continuously* perform verification of your dependencies via your
project's continuous integration system.

An example of configuring this via GitHub Actions is to add this to your
configuration:

```yml
name: CI
on: [push, pull_request]
jobs:
  cargo-vet:
    name: Vet Dependencies
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@master
    - name: Install Rust
      run: rustup update stable && rustup default stable
    - run: cargo install cargo-vet
    - run: cargo vet --locked
```

This will ensure that that all changes made to your repository, either via a PR
or a direct push, have a fully-vetted dependency set.
