# Function: PublicWrapSecretKeyWithPassword()

> **PublicWrapSecretKeyWithPassword**<`V`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"WrapSecretKeyWithPassword"`, <`Options`>(`key`, `password`, `options?`) => `Promise`<`` `k${V}.secret-pw.${string}` ``>>

Creates a composable password-based secret key-wrapping capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicWrapSecretKeyWithPasswordImplementation`](../type-aliases/PublicWrapSecretKeyWithPasswordImplementation.md)<`V`, `S`> | Low-level password-based secret key-wrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"WrapSecretKeyWithPassword"`, <`Options`>(`key`, `password`, `options?`) => `Promise`<`` `k${V}.secret-pw.${string}` ``>>

## Remarks

The installed operation's `options` argument is `PasswordWrapOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
WrapSecretKeyWithPassword(key: S, password: Uint8Array, options?: PasswordWrapOptions<V>): Promise<PasswordWrappedSecretPASERK<V>>
```
