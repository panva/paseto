# Type Alias: PublicWrapSecretKeyImplementation\<V, S, W, Prefix>

> **PublicWrapSecretKeyImplementation**<`V`, `S`, `W`, `Prefix`> = `Readonly`<{ `run`: (`key`, `wrappingKey`) => `Promise`<`` `k${V}.secret-wrap.${Prefix}.${string}` ``>; `version`: `V`; }>

Low-level secret key wrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |
