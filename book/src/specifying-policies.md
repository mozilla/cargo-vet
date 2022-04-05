# Specifying Policies

By default, `cargo vet` checks all transitive dependencies of all top-level
crates against the default criteria for all platforms. In some situations, you
may be able to reduce your workload by encoding your requirements more
precisely, such as:

* **Using different criteria for different top-level crates.** Your workspace
  might contain both a production product and an internal tool, which might
require different levels of audits for their dependencies.
* **Using different criteria for dev- and build-dependencies.** You might decide
  that your main dependency tree should be audited as
  [secure](sample-criteria.md#secure), but that dev- and build-depedencies need
  only be [safe_to_run_locally](sample-criteria.md#safe_to_run_locally).
* **Ignoring targets you don't support.** Some dependencies are only built for
  certain platforms. Additionally, audit records can [specify](audit-entries.md#targets)
  that they do not cover platform-specific code for certain targets. You can
  leverage these details by scoping `cargo vet` to your platforms of interest.

If the default behavior works for you, there's no need to specify anything. If
you wish to encode policies such as the above, you can do so in
[config.toml](config.md#the-policy-table).
