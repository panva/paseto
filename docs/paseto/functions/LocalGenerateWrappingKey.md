# Function: LocalGenerateWrappingKey()

> **LocalGenerateWrappingKey**<`V`, `W`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"GenerateWrappingKey"`, (`options?`) => `Promise`<`W`>>

Creates a composable local wrapping-key generation capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalGenerateWrappingKeyImplementation`](../type-aliases/LocalGenerateWrappingKeyImplementation.md)<`V`, `W`> | Low-level wrapping-key generation implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"GenerateWrappingKey"`, (`options?`) => `Promise`<`W`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
GenerateWrappingKey(options?: KeyOptions): Promise<W>
```
