# Function: LocalImportSealingSecretKey()

> **LocalImportSealingSecretKey**<`V`, `SS`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportSealingSecretKey"`, (`material`, `options?`) => `Promise`<`SS`>>

Creates a composable sealing secret-key import capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalImportSealingSecretKeyImplementation`](../type-aliases/LocalImportSealingSecretKeyImplementation.md)<`V`, `SS`> | Low-level sealing secret-key import implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportSealingSecretKey"`, (`material`, `options?`) => `Promise`<`SS`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportSealingSecretKey(material: Uint8Array, options?: KeyOptions): Promise<SS>
```
