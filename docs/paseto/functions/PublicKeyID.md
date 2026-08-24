# Function: PublicKeyID()

> **PublicKeyID**<`V`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"PublicKeyID"`, (`paserk`) => `Promise`<`` `k${V}.pid.${string}` ``>>

Creates a composable public PASERK ID capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicKeyIDImplementation`](../type-aliases/PublicKeyIDImplementation.md)<`V`> | Low-level public PASERK ID implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"PublicKeyID"`, (`paserk`) => `Promise`<`` `k${V}.pid.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
PublicKeyID(paserk: PublicPASERK<V>): Promise<PublicIdPASERK<V>>
```
