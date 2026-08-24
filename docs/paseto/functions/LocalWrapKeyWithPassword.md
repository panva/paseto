# Function: LocalWrapKeyWithPassword()

> **LocalWrapKeyWithPassword**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"WrapKeyWithPassword"`, <`Options`>(`key`, `password`, `options?`) => `Promise`<`` `k${V}.local-pw.${string}` ``>>

Creates a composable password-based local key-wrapping capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalWrapKeyWithPasswordImplementation`](../type-aliases/LocalWrapKeyWithPasswordImplementation.md)<`V`, `L`> | Low-level password-based local key-wrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"WrapKeyWithPassword"`, <`Options`>(`key`, `password`, `options?`) => `Promise`<`` `k${V}.local-pw.${string}` ``>>

## Remarks

The installed operation's `options` argument is `PasswordWrapOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
WrapKeyWithPassword(key: L, password: Uint8Array, options?: PasswordWrapOptions<V>): Promise<PasswordWrappedLocalPASERK<V>>
```
