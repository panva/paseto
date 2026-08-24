# Function: PublicExportWrappingKey()

> **PublicExportWrappingKey**<`V`, `W`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ExportWrappingKey"`, (`key`) => `Promise`<`Uint8Array`>>

Creates a composable wrapping-key export capability factory for public-purpose keys.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicExportWrappingKeyImplementation`](../type-aliases/PublicExportWrappingKeyImplementation.md)<`V`, `W`> | Low-level wrapping-key export implementation for public-purpose keys |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ExportWrappingKey"`, (`key`) => `Promise`<`Uint8Array`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportWrappingKey(key: W): Promise<Uint8Array>
```
