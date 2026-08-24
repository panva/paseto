# Function: LocalGenerateSealingKeyPair()

> **LocalGenerateSealingKeyPair**<`V`, `SP`, `SS`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"GenerateSealingKeyPair"`, (`options?`) => `Promise`<[`KeyPair`](../interfaces/KeyPair.md)<`SP`, `SS`>>>

Creates a composable sealing key-pair generation capability factory.

The installed operation's `extractable` option applies to the secret key. The public key is
always extractable.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `SP` *extends* [`Key`](../interfaces/Key.md) | Sealing public key representation |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalGenerateSealingKeyPairImplementation`](../type-aliases/LocalGenerateSealingKeyPairImplementation.md)<`V`, `SP`, `SS`> | Low-level sealing key-pair generation implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"GenerateSealingKeyPair"`, (`options?`) => `Promise`<[`KeyPair`](../interfaces/KeyPair.md)<`SP`, `SS`>>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
GenerateSealingKeyPair(options?: KeyOptions): Promise<KeyPair<SP, SS>>
```
