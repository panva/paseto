# Type Alias: PasswordWrapOptions\<V>

> **PasswordWrapOptions**<`V`> = \[`V`] *extends* \[`1` ∣ `3`] ? `object` : \[`V`] *extends* \[`2` ∣ `4`] ? `object` : `Record`<`PropertyKey`, `never`>

Options used when password-wrapping a PASERK. V1 and v3 use PBKDF2 `iterations`; v2 and v4 use
Argon2id `memory`, `passes`, and `parallelism`.

## Version-specific Properties

### Versions 1 and 3

#### iterations?

> `optional` **iterations?**: `number`

PBKDF2 iteration count. Defaults to 100,000.

### Versions 2 and 4

#### memory?

> `optional` **memory?**: `number`

Argon2id memory limit in bytes. Defaults to 64 MiB.

#### parallelism?

> `optional` **parallelism?**: `number`

Degree of Argon2id parallelism. Defaults to 1.

#### passes?

> `optional` **passes?**: `number`

Number of Argon2id passes. Defaults to 2.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK protocol version selecting the parameter set |

## Remarks

All fields are numbers. For v1 and v3, `iterations` defaults to 100,000. For v2 and v4, `memory`,
`passes`, and `parallelism` default to 64 MiB, 2, and 1, respectively.
