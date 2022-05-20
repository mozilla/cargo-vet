# Built-In Criteria

While you can define whatever criteria you like, `cargo vet` includes two
commonly-used audit criteria out of the box. These criteria are automatically
mapped across projects.

## safe-to-run

```
{{#include ../../src/criteria/safe-to-run.txt}}
```

## safe-to-deploy

```
{{#include ../../src/criteria/safe-to-deploy.txt}}
```

This implies `safe-to-run`.
