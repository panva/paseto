# Function: PublicImportPublicKey()

> **PublicImportPublicKey**<`V`, `P`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ImportPublicKey"`, (`paserk`) => `Promise`<`P`>>

Creates a composable public PASERK import capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicImportPublicKeyImplementation`](../type-aliases/PublicImportPublicKeyImplementation.md)<`V`, `P`> | Low-level public PASERK import implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"ImportPublicKey"`, (`paserk`) => `Promise`<`P`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportPublicKey(paserk: PublicPASERK<V>): Promise<P>
```
