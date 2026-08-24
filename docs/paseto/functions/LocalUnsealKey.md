# Function: LocalUnsealKey()

> **LocalUnsealKey**<`V`, `L`, `SS`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"UnsealKey"`, (`paserk`, `recipient`, `options?`) => `Promise`<`L`>>

Creates a composable local key-unsealing capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
| `SS` *extends* [`Key`](../interfaces/Key.md) | Sealing secret key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalUnsealKeyImplementation`](../type-aliases/LocalUnsealKeyImplementation.md)<`V`, `L`, `SS`> | Low-level local key-unsealing implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"UnsealKey"`, (`paserk`, `recipient`, `options?`) => `Promise`<`L`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
UnsealKey(paserk: SealedLocalPASERK<V>, recipient: SS, options?: KeyOptions): Promise<L>
```
