# Multiple Repositories

The discussion thus far assumes the project exists in a single repository, but
it's common for organizations to manage code across multiple repositories. At
first glance this presents a dilemma as to whether to centralize or distribute
the audit records. Putting them all in one place makes them easier to consume,
but more cumbersome to produce, since updating a package in one repository may
require a developer to record a new audit in another repository.

The `cargo vet aggregate` subcommand resolves this tension. The command itself
simply takes a list of audit file URLs, and produces a single merged file[^1].
The recommended workflow is as follows:
1. Create a dedicated repository to host the merged audits ([example](https://github.com/mozilla/supply-chain)).
2. Add a file called `sources.list` to this repository, which contains a plain
   list of URLs for the audit files in each project.
3. Create a recurring task on that repository to invoke `cargo vet aggregate
   sources.list > audits.toml` and commit the result if changed[^2].
4. Add the aggregated audit file to the `imports` table of each individual
   repository.

Beyond streamlining the workflow within the project, this approach also makes it
easy for others to import the full audit set without needing to navigate the
details of various source repositories.

[^1]: The entries in the new file have an additional `aggregated-from` field
      which points to their original location.

[^2]: On GitHub, this can be accomplished by adding the following to
    `.github/workflows/aggregate.yml`:
```yml
name: CI
on:
  schedule:
    # Every five minutes (maximum frequency allowed by GitHub)
    - cron:  '*/5 * * * *'

permissions:
  contents: write

jobs:
  aggregate:
    name: Aggregate Dependencies
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
    - name: Invoke cargo-vet aggregate
      run: cargo vet aggregate --output-file audits.toml sources.list
    - name: Commit changes (if any)
      run: |
        git config --global user.name "cargo-vet[bot]"
        git config --global user.email "cargo-vet-aggregate@invalid"
        git add audits.toml
        git commit -m "Aggregate new audits" || true
    - name: Push changes (if any)
      run: git push origin main
```
