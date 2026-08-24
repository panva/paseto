# Function: LocalUnwrapKeyWithPassword()

> **LocalUnwrapKeyWithPassword**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"UnwrapKeyWithPassword"`, <`Options`>(`paserk`, `password`, `options?`) => `Promise`<`L`>>

Creates a composable password-based local key-unwrapping capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalUnwrapKeyWithPasswordImplementation`](../type-aliases/LocalUnwrapKeyWithPasswordImplementation.md)<`V`, `L`> | Low-level password-based local key-unwrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"UnwrapKeyWithPassword"`, <`Options`>(`paserk`, `password`, `options?`) => `Promise`<`L`>>

## Remarks

The installed operation's `options` argument is `PasswordUnwrapOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
UnwrapKeyWithPassword(paserk: PasswordWrappedLocalPASERK<V>, password: Uint8Array, options?: PasswordUnwrapOptions<V>): Promise<L>
```
