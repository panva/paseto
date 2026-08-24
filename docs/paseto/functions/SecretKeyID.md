# Function: SecretKeyID()

> **SecretKeyID**<`V`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"SecretKeyID"`, (`paserk`) => `Promise`<`` `k${V}.sid.${string}` ``>>

Creates a composable secret PASERK ID capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`SecretKeyIDImplementation`](../type-aliases/SecretKeyIDImplementation.md)<`V`> | Low-level secret PASERK ID implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"SecretKeyID"`, (`paserk`) => `Promise`<`` `k${V}.sid.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
SecretKeyID(paserk: SecretKeyIDInput<V>): Promise<SecretIdPASERK<V>>
```
