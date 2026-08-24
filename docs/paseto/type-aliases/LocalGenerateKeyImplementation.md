# Type Alias: LocalGenerateKeyImplementation\<V, L>

> **LocalGenerateKeyImplementation**<`V`, `L`> = `Readonly`<{ `run`: (`extractable`) => `Promise`<`L`>; `version`: `V`; }>

Low-level local key generation implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
