# Function: PublicUnwrapSecretKey()

> **PublicUnwrapSecretKey**<`V`, `S`, `W`, `Prefix`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"UnwrapSecretKey"`, (`paserk`, `wrappingKey`, `options?`) => `Promise`<`S`>>

Creates a composable secret key-unwrapping capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicUnwrapSecretKeyImplementation`](../type-aliases/PublicUnwrapSecretKeyImplementation.md)<`V`, `S`, `W`, `Prefix`> | Low-level secret key-unwrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"UnwrapSecretKey"`, (`paserk`, `wrappingKey`, `options?`) => `Promise`<`S`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
UnwrapSecretKey(paserk: WrappedSecretPASERK<V, Prefix>, wrappingKey: W, options?: KeyOptions): Promise<S>
```
