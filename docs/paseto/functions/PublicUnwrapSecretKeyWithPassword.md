# Function: PublicUnwrapSecretKeyWithPassword()

> **PublicUnwrapSecretKeyWithPassword**<`V`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"UnwrapSecretKeyWithPassword"`, <`Options`>(`paserk`, `password`, `options?`) => `Promise`<`S`>>

Creates a composable password-based secret key-unwrapping capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicUnwrapSecretKeyWithPasswordImplementation`](../type-aliases/PublicUnwrapSecretKeyWithPasswordImplementation.md)<`V`, `S`> | Low-level password-based secret key-unwrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"UnwrapSecretKeyWithPassword"`, <`Options`>(`paserk`, `password`, `options?`) => `Promise`<`S`>>

## Remarks

The installed operation's `options` argument is `PasswordUnwrapOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
UnwrapSecretKeyWithPassword(paserk: PasswordWrappedSecretPASERK<V>, password: Uint8Array, options?: PasswordUnwrapOptions<V>): Promise<S>
```
