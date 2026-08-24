# Function: PublicGetPublicKey()

> **PublicGetPublicKey**<`V`, `P`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"GetPublicKey"`, (`key`) => `Promise`<`P`>>

Creates a composable public-key derivation capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicGetPublicKeyImplementation`](../type-aliases/PublicGetPublicKeyImplementation.md)<`V`, `P`, `S`> | Low-level public-key derivation implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"GetPublicKey"`, (`key`) => `Promise`<`P`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
GetPublicKey(key: S): Promise<P>
```
