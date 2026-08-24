# Type Alias: PublicExportWrappingKeyImplementation\<V, W>

> **PublicExportWrappingKeyImplementation**<`V`, `W`> = `Readonly`<{ `run`: (`key`) => `Promise`<`Uint8Array`>; `version`: `V`; }>

Low-level wrapping key export implementation for public-purpose keys.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
