# Type Alias: LocalExportSealingSecretKeyImplementation\<V, SS>

> **LocalExportSealingSecretKeyImplementation**<`V`, `SS`> = `Readonly`<{ `run`: (`key`) => `Promise`<`Uint8Array`>; `version`: `V`; }>

Low-level sealing secret key export implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |
