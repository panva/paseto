# Type Alias: LocalUnwrapKeyImplementation\<V, L, W, Prefix>

> **LocalUnwrapKeyImplementation**<`V`, `L`, `W`, `Prefix`> = `Readonly`<{ `run`: (`paserk`, `wrappingKey`, `extractable`) => `Promise`<`L`>; `version`: `V`; }>

Low-level local key unwrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |
