# Function: PublicGenerateWrappingKey()

> **PublicGenerateWrappingKey**<`V`, `W`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"GenerateWrappingKey"`, (`options?`) => `Promise`<`W`>>

Creates a composable wrapping-key generation capability factory for public-purpose keys.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicGenerateWrappingKeyImplementation`](../type-aliases/PublicGenerateWrappingKeyImplementation.md)<`V`, `W`> | Low-level wrapping-key generation implementation for public-purpose keys |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"GenerateWrappingKey"`, (`options?`) => `Promise`<`W`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
GenerateWrappingKey(options?: KeyOptions): Promise<W>
```
