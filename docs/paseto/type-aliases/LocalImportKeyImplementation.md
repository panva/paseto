# Type Alias: LocalImportKeyImplementation\<V, L>

> **LocalImportKeyImplementation**<`V`, `L`> = `Readonly`<{ `run`: (`paserk`, `extractable`) => `Promise`<`L`>; `version`: `V`; }>

Low-level local key import implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
