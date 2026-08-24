# Function: LocalGenerateKey()

> **LocalGenerateKey**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"GenerateKey"`, (`options?`) => `Promise`<`L`>>

Creates a composable local key-generation capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASETO protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalGenerateKeyImplementation`](../type-aliases/LocalGenerateKeyImplementation.md)<`V`, `L`> | Low-level local key-generation implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"GenerateKey"`, (`options?`) => `Promise`<`L`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
GenerateKey(options?: KeyOptions): Promise<L>
```
