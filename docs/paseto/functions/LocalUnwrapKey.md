# Function: LocalUnwrapKey()

> **LocalUnwrapKey**<`V`, `L`, `W`, `Prefix`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"UnwrapKey"`, (`paserk`, `wrappingKey`, `options?`) => `Promise`<`L`>>

Creates a composable local key-unwrapping capability factory.

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
| `implementation` | [`LocalUnwrapKeyImplementation`](../type-aliases/LocalUnwrapKeyImplementation.md)<`V`, `L`, `W`, `Prefix`> | Low-level local key-unwrapping implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"UnwrapKey"`, (`paserk`, `wrappingKey`, `options?`) => `Promise`<`L`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
UnwrapKey(paserk: WrappedLocalPASERK<V, Prefix>, wrappingKey: W, options?: KeyOptions): Promise<L>
```
