# Function: LocalWrapKey()

> **LocalWrapKey**<`V`, `L`, `W`, `Prefix`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"WrapKey"`, (`key`, `wrappingKey`) => `Promise`<`` `k${V}.local-wrap.${Prefix}.${string}` ``>>

Creates a composable local key-wrapping capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `W` *extends* [`Key`](../interfaces/Key.md) | Wrapping key representation |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalWrapKeyImplementation`](../type-aliases/LocalWrapKeyImplementation.md)<`V`, `L`, `W`, `Prefix`> | Low-level local key-wrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"WrapKey"`, (`key`, `wrappingKey`) => `Promise`<`` `k${V}.local-wrap.${Prefix}.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
WrapKey(key: L, wrappingKey: W): Promise<WrappedLocalPASERK<V, Prefix>>
```
