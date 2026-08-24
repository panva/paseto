# Function: PublicExportSecretKey()

> **PublicExportSecretKey**<`V`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ExportSecretKey"`, (`key`) => `Promise`<`` `k${V}.secret.${string}` ``>>

Creates a composable secret PASERK export capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicExportSecretKeyImplementation`](../type-aliases/PublicExportSecretKeyImplementation.md)<`V`, `S`> | Low-level secret PASERK export implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ExportSecretKey"`, (`key`) => `Promise`<`` `k${V}.secret.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportSecretKey(key: S): Promise<SecretPASERK<V>>
```
