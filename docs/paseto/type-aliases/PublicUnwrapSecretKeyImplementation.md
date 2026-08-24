# Type Alias: PublicUnwrapSecretKeyImplementation\<V, S, W, Prefix>

> **PublicUnwrapSecretKeyImplementation**<`V`, `S`, `W`, `Prefix`> = `Readonly`<{ `run`: (`paserk`, `wrappingKey`, `extractable`) => `Promise`<`S`>; `version`: `V`; }>

Low-level secret key unwrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |
