# Type Alias: PublicProtocolInstance\<F>

> **PublicProtocolInstance**<`F`> = readonly public operation methods selected by `F`

A public protocol exposing exactly the selected capabilities.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `F` *extends* [`PublicProtocolFactories`](PublicProtocolFactories.md) | Non-empty tuple of selected public-purpose capability factories |

## Resulting Methods

Each selected factory contributes one method named after its operation. The method retains the parameter and return types carried by that factory.
