# Function: LocalImportKey()

> **LocalImportKey**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportKey"`, (`paserk`, `options?`) => `Promise`<`L`>>

Creates a composable local PASERK import capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalImportKeyImplementation`](../type-aliases/LocalImportKeyImplementation.md)<`V`, `L`> | Low-level local PASERK import implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ImportKey"`, (`paserk`, `options?`) => `Promise`<`L`>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ImportKey(paserk: LocalPASERK<V>, options?: KeyOptions): Promise<L>
```
