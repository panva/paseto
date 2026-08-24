# Function: PublicImportSecretKey()

> **PublicImportSecretKey**<`V`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ImportSecretKey"`, (`paserk`, `options?`) => `Promise`<`S`>>

Creates a composable secret PASERK import capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicImportSecretKeyImplementation`](../type-aliases/PublicImportSecretKeyImplementation.md)<`V`, `S`> | Low-level secret PASERK import implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ImportSecretKey"`, (`paserk`, `options?`) => `Promise`<`S`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportSecretKey(paserk: SecretPASERK<V>, options?: KeyOptions): Promise<S>
```
