# Type Alias: LocalProtocolInstance\<F>

> **LocalProtocolInstance**<`F`> = readonly local operation methods selected by `F`

A local protocol exposing exactly the selected capabilities.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `F` *extends* [`LocalProtocolFactories`](LocalProtocolFactories.md) | Non-empty tuple of selected local-purpose capability factories |

## Resulting Methods

Each selected factory contributes one method named after its operation. The method retains the parameter and return types carried by that factory.
