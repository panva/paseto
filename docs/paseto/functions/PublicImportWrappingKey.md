# Function: PublicImportWrappingKey()

> **PublicImportWrappingKey**<`V`, `W`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ImportWrappingKey"`, (`material`, `options?`) => `Promise`<`W`>>

Creates a composable wrapping-key import capability factory for public-purpose keys.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicImportWrappingKeyImplementation`](../type-aliases/PublicImportWrappingKeyImplementation.md)<`V`, `W`> | Low-level wrapping-key import implementation for public-purpose keys |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ImportWrappingKey"`, (`material`, `options?`) => `Promise`<`W`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<W>
```
