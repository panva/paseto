# Function: PublicVerify()

> **PublicVerify**<`V`, `P`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"Verify"`, <`Options`>(`key`, `token`, `options?`) => `Promise`<[`TokenResult`](../interfaces/TokenResult.md)<[`Claims`](../type-aliases/Claims.md)>>>

Creates a composable public-token verification capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASETO protocol version implemented by the capability |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicVerifyImplementation`](../type-aliases/PublicVerifyImplementation.md)<`V`, `P`> | Low-level public-token verification implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"Verify"`, <`Options`>(`key`, `token`, `options?`) => `Promise`<[`TokenResult`](../interfaces/TokenResult.md)<[`Claims`](../type-aliases/Claims.md)>>>

## Remarks

The installed operation's `options` argument is `ConsumeOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
Verify(key: P, token: string, options?: ConsumeOptions<V>): Promise<TokenResult>
```
