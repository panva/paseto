# Function: PublicExportPublicKey()

> **PublicExportPublicKey**<`V`, `P`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ExportPublicKey"`, (`key`) => `Promise`<`` `k${V}.public.${string}` ``>>

Creates a composable public PASERK export capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicExportPublicKeyImplementation`](../type-aliases/PublicExportPublicKeyImplementation.md)<`V`, `P`> | Low-level public PASERK export implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ExportPublicKey"`, (`key`) => `Promise`<`` `k${V}.public.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportPublicKey(key: P): Promise<PublicPASERK<V>>
```
