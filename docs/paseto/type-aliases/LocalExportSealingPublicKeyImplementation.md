# Type Alias: LocalExportSealingPublicKeyImplementation\<V, SP>

> **LocalExportSealingPublicKeyImplementation**<`V`, `SP`> = `Readonly`<{ `run`: (`key`) => `Promise`<`Uint8Array`>; `version`: `V`; }>

Low-level sealing public key export implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |
