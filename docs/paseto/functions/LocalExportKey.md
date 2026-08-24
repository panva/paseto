# Function: LocalExportKey()

> **LocalExportKey**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportKey"`, (`key`) => `Promise`<`` `k${V}.local.${string}` ``>>

Creates a composable local PASERK export capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASERK protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalExportKeyImplementation`](../type-aliases/LocalExportKeyImplementation.md)<`V`, `L`> | Low-level local PASERK export implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"ExportKey"`, (`key`) => `Promise`<`` `k${V}.local.${string}` ``>>

## Installed Operation

The returned capability factory installs the following protocol method.

```text
ExportKey(key: L): Promise<LocalPASERK<V>>
```
