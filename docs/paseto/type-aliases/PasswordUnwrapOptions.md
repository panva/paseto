# Type Alias: PasswordUnwrapOptions\<V>

> **PasswordUnwrapOptions**<`V`> = [`KeyOptions`](../interfaces/KeyOptions.md) & \[`V`] *extends* \[`1` ∣ `3`] ? `object` : \[`V`] *extends* \[`2` ∣ `4`] ? `object` : `object`

Options used when unwrapping a password-protected PASERK. All versions support `extractable`; v1
and v3 support `maxIterations`, while v2 and v4 support `maxMemory`, `maxPasses`, and
`maxParallelism`.

## Version-specific Properties

### Versions 1 and 3

#### maxIterations?

> `optional` **maxIterations?**: `number`

Maximum PBKDF2 iterations accepted. Defaults to 1,000,000.

### Versions 2 and 4

#### maxMemory?

> `optional` **maxMemory?**: `number`

Maximum Argon2 memory in bytes accepted. Defaults to 1 GiB.

#### maxParallelism?

> `optional` **maxParallelism?**: `number`

Maximum Argon2 parallelism accepted. Defaults to 16.

#### maxPasses?

> `optional` **maxPasses?**: `number`

Maximum Argon2 passes accepted. Defaults to 10.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK version selecting PBKDF2 limits for v1/v3 or Argon2id limits for v2/v4 |

## Remarks

`extractable` follows [KeyOptions](../interfaces/KeyOptions.md). All limit fields are numbers. For v1 and v3,
`maxIterations` defaults to 1,000,000. For v2 and v4, `maxMemory`, `maxPasses`, and
`maxParallelism` default to 1 GiB, 10, and 16, respectively.
