# Type Alias: LocalProtocolFactories\<V>

> **LocalProtocolFactories**<`V`> = readonly \[[`LocalCapabilityFactory`](LocalCapabilityFactory.md)<`V`>, `...LocalCapabilityFactory<V>[]`]

A non-empty tuple of local-purpose capability factories.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASETO and PASERK protocol versions permitted for tuple elements |
