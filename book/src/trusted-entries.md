# Trusted Package Entries

This section defines the semantics of the various keys that may be specified in trusted table
entries.

## `criteria`

Specifies the relevant criteria under which the crate and publisher is trusted. This field is
required. This may be a single criteria or an array of criteria.

## `user-id`

Specified the user id of the user which is trusted. Note that this is the `crates.io` user id, not
the user ame.

## `start`

Earliest day of publication which should be considered trusted for the crate and user. Crates
published by the user before this date will not be considered as certified. This field is required.

Note that publication dates use UTC rather than local time.

## `end`

Latest day of publication which should be considered trusted for the crate and user. Crates
published by the user after this date will not be considered as certified. This date may be at most
1 year in the future. This field is required.

Note that publication dates use UTC rather than local time.

## `notes`

An optional free-form string containing any information regarding the trust of this crate and user.
