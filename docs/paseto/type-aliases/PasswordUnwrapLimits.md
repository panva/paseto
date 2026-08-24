# Type Alias: PasswordUnwrapLimits\<V>

> **PasswordUnwrapLimits**<`V`> = \[`V`] *extends* \[`1` ∣ `3`] ? `object` : \[`V`] *extends* \[`2` ∣ `4`] ? `object` : `Record`<`PropertyKey`, `never`>

Resource limits passed to a low-level password-unwrapping implementation. V1 and v3 receive
`maxIterations`; v2 and v4 receive `maxMemory`, `maxPasses`, and `maxParallelism`.

The protocol adapter validates the caller's options and handles key extractability separately.

## Version-specific Properties

### Versions 1 and 3

#### maxIterations?

> `optional` **maxIterations?**: `number`

### Versions 2 and 4

#### maxMemory?

> `optional` **maxMemory?**: `number`

#### maxParallelism?

> `optional` **maxParallelism?**: `number`

#### maxPasses?

> `optional` **maxPasses?**: `number`

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK version selecting PBKDF2 limits for v1/v3 or Argon2id limits for v2/v4 |
