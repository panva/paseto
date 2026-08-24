# Function: LocalDecrypt()

> **LocalDecrypt**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"Decrypt"`, <`Options`>(`key`, `token`, `options?`) => `Promise`<[`TokenResult`](../interfaces/TokenResult.md)<[`Claims`](../type-aliases/Claims.md)>>>

Creates a composable local-token decryption capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASETO protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalDecryptImplementation`](../type-aliases/LocalDecryptImplementation.md)<`V`, `L`> | Low-level local-token decryption implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"Decrypt"`, <`Options`>(`key`, `token`, `options?`) => `Promise`<[`TokenResult`](../interfaces/TokenResult.md)<[`Claims`](../type-aliases/Claims.md)>>>

## Remarks

The installed operation's `options` argument is `ConsumeOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
Decrypt(key: L, token: string, options?: ConsumeOptions<V>): Promise<TokenResult>
```
