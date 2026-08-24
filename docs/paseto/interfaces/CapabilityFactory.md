# Interface: CapabilityFactory()\<P, V, O, R>

A protocol-operation factory returned by a root operation creator and recognized by protocol
constructors. Its structural callable type permits composition across package copies; runtime
recognition is not a provenance guarantee.

## Contents

- [Type Parameters](#type-parameters)
- [Returns](#returns)

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `P` *extends* [`Purpose`](../type-aliases/Purpose.md) | Protocol purpose bound to the capability |
| `V` *extends* [`Version`](../type-aliases/Version.md) | Protocol version bound to the capability |
| `O` *extends* `string` | Operation name bound to the capability |
| `R` *extends* (...`args`) => `unknown` | Operation call signature |

> **CapabilityFactory**(): `Readonly`<{ `operation`: `O`; `purpose`: `P`; `run`: `R`; `version`: `V`; }>

Creates the validated, protocol-bound operation installed by a protocol constructor.

## Returns

`Readonly`<{ `operation`: `O`; `purpose`: `P`; `run`: `R`; `version`: `V`; }>
