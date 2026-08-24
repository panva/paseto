# Type Alias: PublicVerifyImplementation\<V, P>

> **PublicVerifyImplementation**<`V`, `P`> = `Readonly`<{ `run`: (`key`, `message`, `signature`, `footer`, ...`implicitAssertion`) => `Promise`<`boolean`>; `version`: `V`; }>

Low-level public token verification implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |

## Remarks

In v1 and v2, `run` receives `key`, `message`, `signature`, and `footer`. In v3 and v4, it also
receives a required final `implicitAssertion` argument as a `Uint8Array`.
