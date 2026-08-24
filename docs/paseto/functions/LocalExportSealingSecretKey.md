# Function: LocalExportSealingSecretKey()

> **LocalExportSealingSecretKey**<`V`, `SS`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportSealingSecretKey"`, (`key`) => `Promise`<`Uint8Array`>>

Creates a composable sealing secret-key export capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalExportSealingSecretKeyImplementation`](../type-aliases/LocalExportSealingSecretKeyImplementation.md)<`V`, `SS`> | Low-level sealing secret-key export implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportSealingSecretKey"`, (`key`) => `Promise`<`Uint8Array`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportSealingSecretKey(key: SS): Promise<Uint8Array>
```
