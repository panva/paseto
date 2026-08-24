# Type Alias: WrappedSecretPASERK\<V, Prefix>

> **WrappedSecretPASERK**<`V`, `Prefix`> = `` `k${V}.secret-wrap.${Prefix}.${string}` ``

A symmetrically wrapped secret-key PASERK.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASERK protocol version encoded by the serialization |
| `Prefix` *extends* `string` | Key-wrapping protocol prefix |
