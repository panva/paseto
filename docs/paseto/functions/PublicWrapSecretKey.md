# Function: PublicWrapSecretKey()

> **PublicWrapSecretKey**<`V`, `S`, `W`, `Prefix`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"WrapSecretKey"`, (`key`, `wrappingKey`) => `Promise`<`` `k${V}.secret-wrap.${Prefix}.${string}` ``>>

Creates a composable secret key-wrapping capability factory.

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
| `implementation` | [`PublicWrapSecretKeyImplementation`](../type-aliases/PublicWrapSecretKeyImplementation.md)<`V`, `S`, `W`, `Prefix`> | Low-level secret key-wrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"WrapSecretKey"`, (`key`, `wrappingKey`) => `Promise`<`` `k${V}.secret-wrap.${Prefix}.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
WrapSecretKey(key: S, wrappingKey: W): Promise<WrappedSecretPASERK<V, Prefix>>
```
