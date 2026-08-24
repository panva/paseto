# Function: LocalSealKey()

> **LocalSealKey**<`V`, `L`, `SP`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"SealKey"`, (`key`, `recipient`) => `Promise`<`` `k${V}.seal.${string}` ``>>

Creates a composable local key-sealing capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalSealKeyImplementation`](../type-aliases/LocalSealKeyImplementation.md)<`V`, `L`, `SP`> | Low-level local key-sealing implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"SealKey"`, (`key`, `recipient`) => `Promise`<`` `k${V}.seal.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
SealKey(key: L, recipient: SP): Promise<SealedLocalPASERK<V>>
```
