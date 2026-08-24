# Type Alias: LocalGenerateWrappingKeyImplementation\<V, W>

> **LocalGenerateWrappingKeyImplementation**<`V`, `W`> = `Readonly`<{ `run`: (`extractable`) => `Promise`<`W`>; `version`: `V`; }>

Low-level wrapping key generation implementation for local-purpose keys.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
