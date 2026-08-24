# Type Alias: LocalImportSealingSecretKeyImplementation\<V, SS>

> **LocalImportSealingSecretKeyImplementation**<`V`, `SS`> = `Readonly`<{ `run`: (`material`, `extractable`) => `Promise`<`SS`>; `version`: `V`; }>

Low-level sealing secret key import implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |
