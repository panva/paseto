# Function: LocalImportWrappingKey()

> **LocalImportWrappingKey**<`V`, `W`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportWrappingKey"`, (`material`, `options?`) => `Promise`<`W`>>

Creates a composable local wrapping-key import capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalImportWrappingKeyImplementation`](../type-aliases/LocalImportWrappingKeyImplementation.md)<`V`, `W`> | Low-level wrapping-key import implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportWrappingKey"`, (`material`, `options?`) => `Promise`<`W`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<W>
```
