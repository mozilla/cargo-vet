# Sample Criteria

This section contains sample text for potential criteria you might define for
your project. Since the tool is agnostic the content of the criteria, you are
free to adopt them wholesale or modify them in whatever way makes sense for
your project. That said, hewing closely to the defaults when workable may make
it easier to map audits between your project and other projects that also use
those defaults.

As a convention, it is assumed that the set of individuals who can certify
audits is the same as those who can approve code changes to the repository that
hosts them (i.e. project committers). Deviations from this should be specified
explicitly in the criteria description.

## safe_to_run_locally

```
This crate can be compiled, run, and tested on a workstation or in automation
without surprising consequences, such as:
* Reading or writing data from sensitive or unrelated parts of the filesystem.
* Installing software or reconfiguring the device.
* Connecting to untrusted network endpoints.
* Misuse of system resources (e.g. crytocurrency mining).
```

## secure

```
{{#include criteria_text_secure.md}}
```

## sound

```
Assuming its dependencies are also sound, consumers cannot use this crate to
generate undefined behavior without using `unsafe`.

This is trivially true for a crate with no `unsafe` code. Verifying the
soundness of `unsafe` blocks can require significant expertise — when in doubt
consult a Rust expert.
```

## reviewed

```
This crate has undergone a full line-by-line code review, and meets the same
standards as would be applied to first-party code.
```

## crypto_reviewed

```
The cryptographic code in this crate has been reviewed for correctness by a
member of a designated set of cryptography experts within the project.
```
