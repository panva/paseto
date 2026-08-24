# Function: LocalExportSealingPublicKey()

> **LocalExportSealingPublicKey**<`V`, `SP`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportSealingPublicKey"`, (`key`) => `Promise`<`Uint8Array`>>

Creates a composable sealing public-key export capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalExportSealingPublicKeyImplementation`](../type-aliases/LocalExportSealingPublicKeyImplementation.md)<`V`, `SP`> | Low-level sealing public-key export implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportSealingPublicKey"`, (`key`) => `Promise`<`Uint8Array`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportSealingPublicKey(key: SP): Promise<Uint8Array>
```
