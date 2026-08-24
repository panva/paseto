# Type Alias: LocalDecryptImplementation\<V, L>

> **LocalDecryptImplementation**<`V`, `L`> = `Readonly`<{ `run`: (`key`, `input`, `footer`, ...`implicitAssertion`) => `Promise`<`Uint8Array`>; `version`: `V`; }>

Low-level local token decryption implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Remarks

In v1 and v2, `run` receives `key`, `input`, and `footer`. In v3 and v4, it also receives a
required final `implicitAssertion` argument as a `Uint8Array`.
