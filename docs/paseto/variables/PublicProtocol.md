# Variable: PublicProtocol

> `const` **PublicProtocol**: new <`F`>(...`factories`) => [`PublicProtocolInstance`](../type-aliases/PublicProtocolInstance.md)<`F`>

Composes selected public-purpose capabilities into a same-version protocol instance.

Creates a public-purpose protocol exposing exactly the selected capabilities. `F` is inferred
as the non-empty tuple of supplied factory arguments.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| ...`factories` | `F` | Same-version public-purpose capability factories with unique operations |

## Returns

[`PublicProtocolInstance`](../type-aliases/PublicProtocolInstance.md)<`F`>
