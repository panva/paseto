# Type Alias: LocalExportKeyImplementation\<V, L>

> **LocalExportKeyImplementation**<`V`, `L`> = `Readonly`<{ `run`: (`key`) => `Promise`<`` `k${V}.local.${string}` ``>; `version`: `V`; }>

Low-level local key export implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
