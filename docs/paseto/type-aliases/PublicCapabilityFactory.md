# Type Alias: PublicCapabilityFactory\<V, O, R>

> **PublicCapabilityFactory**<`V`, `O`, `R`> = [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `O`, `R`>

One public-purpose capability factory accepted by [PublicProtocol](../variables/PublicProtocol.md).

When `O` is a specific operation, `R` defaults to that operation's callable signature. Supply `R`
to retain a more specific signature for a custom key representation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASETO and PASERK protocol version |
| `O` *extends* [`PublicOperation`](PublicOperation.md) | Public-purpose operation name |
| `R` *extends* (...`args`) => `unknown` | Installed operation signature |
