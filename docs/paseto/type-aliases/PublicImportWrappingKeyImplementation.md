# Type Alias: PublicImportWrappingKeyImplementation\<V, W>

> **PublicImportWrappingKeyImplementation**<`V`, `W`> = `Readonly`<{ `run`: (`material`, `extractable`) => `Promise`<`W`>; `version`: `V`; }>

Low-level wrapping key import implementation for public-purpose keys.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
