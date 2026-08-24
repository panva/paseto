# Type Alias: LocalWrapKeyImplementation\<V, L, W, Prefix>

> **LocalWrapKeyImplementation**<`V`, `L`, `W`, `Prefix`> = `Readonly`<{ `run`: (`key`, `wrappingKey`) => `Promise`<`` `k${V}.local-wrap.${Prefix}.${string}` ``>; `version`: `V`; }>

Low-level local key wrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |
