# Type Alias: LocalGenerateSealingKeyPairImplementation\<V, SP, SS>

> **LocalGenerateSealingKeyPairImplementation**<`V`, `SP`, `SS`> = `Readonly`<{ `run`: (`extractable`) => `Promise`<[`KeyPair`](../interfaces/KeyPair.md)<`SP`, `SS`>>; `version`: `V`; }>

Low-level sealing key pair generation implementation.

`extractable` applies to the secret key. Sealing public keys are always extractable.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |
