# Audit Criteria

Before you can go about auditing code, you need to decide what you want the
audits to entail. This is expressed with "audit criteria", which are just labels
corresponding to human-readable descriptions of what to check for.

`cargo vet` comes pre-equipped with two built-in criteria:
[safe-to-run](built-in-criteria.md#safe-to-run) and
[safe-to-deploy](built-in-criteria.md#safe-to-deploy). You can use these without
any additional configuration.

## Custom Criteria

You can also specify arbitrary custom criteria in `audits.toml`. For example:

```
[criteria.crypto-reviewed]
description = '''
The cryptographic code in this crate has been reviewed for correctness by a
member of a designated set of cryptography experts within the project.
'''
```

The full feature set is documented [here](config.md#the-criteria-table).

If you are using [aggregated audits](multiple-repositories.md), the
`description` of each criteria must be **exactly identical** in every
repository, or the aggregation will fail.

## Multiple Sets of Criteria

There are a number of reasons you might wish to operate with multiple sets of
criteria:
* **Applying extra checks to some crates:** For example, you might define
  `crypto-reviewed` criteria and require them for audits of crates which
  implement cryptographic algorithms that your application depends on.

* **Relaxing your audit requirements for some crates:** For example, you might
  decide that crates not exposed in production can just be `safe-to-run`
  rather than `safe-to-deploy`, since they don't need to be audited for handling
  adversarial input.

    ```
    [policy.mycrate]
    criteria = ["safe-to-deploy"]
    dependency-criteria = { non-exposed-crate = ["safe-to-run"] }
    ```

* **Improving Sharing:** If one project wants to audit for issues A and B, and
  another project wants to audit for B and C, defining separate sets of criteria
  for A, B, and C allows the two projects to partially share work.

You can define and use as many separate sets of criteria as you like.

### Example criteria set: Google's `ub-risk-N`

Google's rust crate audits define a set of 7 audit criteria that form an
implication chain: `ub-risk-0` through `ub-risk-4`, along with
`ub-risk-1-thorough` and `ub-risk-2-thorough` indicating that two unsafe Rust
experts performed the audit. Most projects that want to use this critera set
should specify `ub-risk-2` as the policy criteria and specify per-crate
policy exceptions for `ub-risk-3` crates.

A notable feature of this criteria set is that it allows you to record an audit
for a crate that your organization has decided is unacceptable for use
(`ub-risk-4`), which can assist in tracking whether the issues have been fixed
when you revisit the crate in the future.

The criteria can be viewed in the `[registry.google]` link in `registry.toml`
and at <https://github.com/google/rust-crate-audits/blob/main/auditing_standards.md>.
