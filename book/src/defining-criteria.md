# Defining Criteria

Before you can go about importing or performing audits, you need to define what
you want the audits to entail. This is specified, in prose, via the `[criteria]`
section of `audited.toml`. These descriptions should be concise, but have enough
detail so that auditors know what's expected of them, and other projects know
how to interpret the results.

## The Basics

In its simplest form, it looks something like this:

```
[criteria]

secure = '''
{{#include criteria_text_secure.md}}
'''
```

The Reference section provides a number of additional [sample
criteria](sample-criteria.md) aimed at different objectives, but ultimately you
are free to specify whatever criteria make sense for your project. Just be
mindful of how they map to the criteria of other projects, since being able to
share audits with others is a big advantage.

## Multiple Sets of Criteria

There are a number of reasons you might wish to define multiple sets of
criteria:
* **Applying extra checks to some crates:** For example, you might define
  `crypto-reviewed` criteria and require them for audits of crates which
  implement cryptographic algorithms that your application depends on.
* **Relaxing your audit requirements for some crates:** For example, you might
  decide that `dev-dependencies` and `build-dependencies` not shipped in your
  actual application don't need to be audited for handling adversarial input.
* **Improving Sharing:** If one project wants to audit for issues A and B, and
  another project want to audit for B and C, defining separate sets of criteria
  for A, B, and C allows the two projects to partially share work.

You can define as many separate sets of criteria as you like, so long as you
[designate a default](config.md#default-criteria).
