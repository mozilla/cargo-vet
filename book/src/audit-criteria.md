# Audit Criteria

Before you can go about auditing code, you need to decide what you want the
audits to entail. This is expressed with "audit criteria", which are just labels
corresponding to human-readable descriptions of what to check for.

`cargo vet` comes pre-equipped with a handful of built-in criteria:
[safe-to-build](built-in-criteria.md#safe-to-build),
[safe-to-run](built-in-criteria.md#safe-to-run), and
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
* **Improving Sharing:** If one project wants to audit for issues A and B, and
  another project want to audit for B and C, defining separate sets of criteria
  for A, B, and C allows the two projects to partially share work.

You can define and use as many separate sets of criteria as you like.
