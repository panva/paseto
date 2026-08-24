# Function: LocalKeyID()

> **LocalKeyID**<`V`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"KeyID"`, (`paserk`) => `Promise`<`` `k${V}.lid.${string}` ``>>

Creates a composable local PASERK ID capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalKeyIDImplementation`](../type-aliases/LocalKeyIDImplementation.md)<`V`> | Low-level local PASERK ID implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"KeyID"`, (`paserk`) => `Promise`<`` `k${V}.lid.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
KeyID(paserk: LocalKeyIDInput<V>): Promise<LocalIdPASERK<V>>
```
