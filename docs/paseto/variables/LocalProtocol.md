# Variable: LocalProtocol

> `const` **LocalProtocol**: new <`F`>(...`factories`) => [`LocalProtocolInstance`](../type-aliases/LocalProtocolInstance.md)<`F`>

Composes selected local-purpose capabilities into a same-version protocol instance.

Creates a local-purpose protocol exposing exactly the selected capabilities. `F` is inferred as
the non-empty tuple of supplied factory arguments.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| ...`factories` | `F` | Same-version local-purpose capability factories with unique operations |

## Returns

[`LocalProtocolInstance`](../type-aliases/LocalProtocolInstance.md)<`F`>
