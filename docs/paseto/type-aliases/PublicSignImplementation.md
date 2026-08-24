# Type Alias: PublicSignImplementation\<V, S>

> **PublicSignImplementation**<`V`, `S`> = `Readonly`<{ `run`: (`key`, `message`, `footer`, ...`implicitAssertion`) => `Promise`<`Uint8Array`>; `version`: `V`; }>

Low-level public token signing implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Remarks

In v1 and v2, `run` receives `key`, `message`, and `footer`. In v3 and v4, it also receives a
required final `implicitAssertion` argument as a `Uint8Array`.
