# Type Alias: LocalCapabilityFactory\<V, O, R>

> **LocalCapabilityFactory**<`V`, `O`, `R`> = [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `O`, `R`>

One local-purpose capability factory accepted by [LocalProtocol](../variables/LocalProtocol.md).

When `O` is a specific operation, `R` defaults to that operation's callable signature. Supply `R`
to retain a more specific signature for a custom key representation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | PASETO and PASERK protocol version |
| `O` *extends* [`LocalOperation`](LocalOperation.md) | Local-purpose operation name |
| `R` *extends* (...`args`) => `unknown` | Installed operation signature |
