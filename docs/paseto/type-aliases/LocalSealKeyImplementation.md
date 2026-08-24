# Type Alias: LocalSealKeyImplementation\<V, L, SP>

> **LocalSealKeyImplementation**<`V`, `L`, `SP`> = `Readonly`<{ `run`: (`key`, `recipient`) => `Promise`<`` `k${V}.seal.${string}` ``>; `version`: `V`; }>

Low-level local key sealing implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |
