# Built-In Criteria

While you can define whatever criteria you like, `cargo vet` includes a handful
of commonly-used audit criteria out of the box. These criteria are automatically
mapped across projects.

## safe_to_build

```
This crate either has no build script, or running its build script will not
result in surprising consequences, such as:
{{#include fragment_surprising_consequences.md}}
```

As a convenience, `cargo vet` will automatically apply this label to any crate
without a custom build script.

## safe_to_run

```
This crate can be compiled, run, and tested on a local workstation or in
controlled automation without surprising consequences, such as:
{{#include fragment_surprising_consequences.md}}
```

This implies `safe_to_build`.

## safe_to_deploy

```
This crate will not introduce a serious security vulnerability to production
software exposed to untrusted input.

Auditors are not required to perform a full logic review of the entire crate.
Rather, they must review enough to fully reason about the behavior of all unsafe
blocks and usage of powerful imports. For any reasonable usage of the crate in
real-world software, an attacker must not be able to manipulate the runtime
behavior of these sections in an exploitable or surprising way.

Ideally, all unsafe code is fully sound, and ambient capabilities (e.g.
filesystem access) are hardened against manipulation and consistent with the
advertised behavior of the crate. However, some discretion is permitted. In such
cases, the nature of the discretion should be recorded in the `notes` field of
the audit record.
```

This implies `safe_to_run`.
