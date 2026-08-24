# Type Alias: WrappedLocalPASERK\<V, Prefix>

> **WrappedLocalPASERK**<`V`, `Prefix`> = `` `k${V}.local-wrap.${Prefix}.${string}` ``

A symmetrically wrapped local-key PASERK.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK protocol version encoded by the serialization |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |
