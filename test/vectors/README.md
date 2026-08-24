# PASETO Test Vectors

See [this repository](https://github.com/paseto-standard/paseto-spec)
for the PASETO specification.

This repository contains the JSON-encoded test vectors for the various
PASETO token formats, as well as for optional PASETO extensions.

You may not need every attribute within a given test. We erred on the
side of over-specifying, rather than under-specifying.

## PASETO Test Vector Requirements

At minimum, implementors **MUST** verify that the `token` decodes to
`payload` when `expect-fail` is set to `false`.  If `expect-fail` is set
to `true`, `payload` **MUST NOT** decode; an error state must be
the result of such operations (e.g. an exception is thrown).

When the keys are provided in multiple formats (raw binary OR PEM),
implementors **MAY** select which test vector is easier to work with.
