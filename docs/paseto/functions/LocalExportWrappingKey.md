# Function: LocalExportWrappingKey()

> **LocalExportWrappingKey**<`V`, `W`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportWrappingKey"`, (`key`) => `Promise`<`Uint8Array`>>

Creates a composable local wrapping-key export capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalExportWrappingKeyImplementation`](../type-aliases/LocalExportWrappingKeyImplementation.md)<`V`, `W`> | Low-level wrapping-key export implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportWrappingKey"`, (`key`) => `Promise`<`Uint8Array`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportWrappingKey(key: W): Promise<Uint8Array>
```
