# Configuring CI

As a final step in setting up a project, you should enable verification to run
as part of your project's continuous integration system.

If your project is hosted on GitHub, you can accomplish this by adding the
following to a new or existing `.yml` file in `.github/workflows` (with `X.Y.Z`
replaced with your desired version):

```yml
name: CI
on: [push, pull_request]
jobs:
  cargo-vet:
    name: Vet Dependencies
    runs-on: ubuntu-latest
    env:
      CARGO_VET_VERSION: X.Y.Z
    steps:
    - uses: actions/checkout@master
    - name: Install Rust
      run: rustup update stable && rustup default stable
    - uses: actions/cache@v2
      with:
        path: ${{ runner.tool_cache }}/cargo-vet
        key: cargo-vet-bin-${{ env.CARGO_VET_VERSION }}
    - name: Add the tool cache directory to the search path
      run: echo "${{ runner.tool_cache }}/cargo-vet/bin" >> $GITHUB_PATH
    - name: Ensure that the tool cache is populated with the cargo-vet binary
      run: cargo install --root ${{ runner.tool_cache }}/cargo-vet --version ${{ env.CARGO_VET_VERSION }} cargo-vet
    - name: Invoke cargo-vet
      run: cargo vet --locked
```

This will ensure that that all changes made to your repository, either via a PR
or a direct push, have a fully-vetted dependency set. The extra logic around the
tool cache allows GitHub to persist a copy of the cargo-vet binary rather than
compiling it from scratch each time, enabling results to be displayed within a
few seconds rather than several minutes.
