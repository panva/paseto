# Function: LocalImportSealingPublicKey()

> **LocalImportSealingPublicKey**<`V`, `SP`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportSealingPublicKey"`, (`material`) => `Promise`<`SP`>>

Creates a composable sealing public-key import capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalImportSealingPublicKeyImplementation`](../type-aliases/LocalImportSealingPublicKeyImplementation.md)<`V`, `SP`> | Low-level sealing public-key import implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportSealingPublicKey"`, (`material`) => `Promise`<`SP`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportSealingPublicKey(material: Uint8Array): Promise<SP>
```
