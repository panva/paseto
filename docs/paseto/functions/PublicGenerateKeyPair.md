# Function: PublicGenerateKeyPair()

> **PublicGenerateKeyPair**<`V`, `P`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"GenerateKeyPair"`, (`options?`) => `Promise`<[`KeyPair`](../interfaces/KeyPair.md)<`P`, `S`>>>

Creates a composable public key-pair generation capability factory.

The installed operation's `extractable` option applies to the secret signing key. The public
verification key is always extractable.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASETO protocol version implemented by the capability |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicGenerateKeyPairImplementation`](../type-aliases/PublicGenerateKeyPairImplementation.md)<`V`, `P`, `S`> | Low-level public key-pair generation implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"GenerateKeyPair"`, (`options?`) => `Promise`<[`KeyPair`](../interfaces/KeyPair.md)<`P`, `S`>>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<P, S>>
```
