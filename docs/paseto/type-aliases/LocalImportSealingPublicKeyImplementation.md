# Type Alias: LocalImportSealingPublicKeyImplementation\<V, SP>

> **LocalImportSealingPublicKeyImplementation**<`V`, `SP`> = `Readonly`<{ `run`: (`material`) => `Promise`<`SP`>; `version`: `V`; }>

Low-level sealing public key import implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |
