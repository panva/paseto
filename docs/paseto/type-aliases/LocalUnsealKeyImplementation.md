# Type Alias: LocalUnsealKeyImplementation\<V, L, SS>

> **LocalUnsealKeyImplementation**<`V`, `L`, `SS`> = `Readonly`<{ `run`: (`paserk`, `recipient`, `extractable`) => `Promise`<`L`>; `version`: `V`; }>

Low-level local key unsealing implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |
