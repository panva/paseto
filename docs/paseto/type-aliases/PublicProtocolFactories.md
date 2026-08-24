# Type Alias: PublicProtocolFactories\<V>

> **PublicProtocolFactories**<`V`> = readonly \[[`PublicCapabilityFactory`](PublicCapabilityFactory.md)<`V`>, `...PublicCapabilityFactory<V>[]`]

A non-empty tuple of public-purpose capability factories.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASETO and PASERK protocol versions permitted for tuple elements |
