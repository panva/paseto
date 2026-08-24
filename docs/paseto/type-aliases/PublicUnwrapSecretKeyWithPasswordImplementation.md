# Type Alias: PublicUnwrapSecretKeyWithPasswordImplementation\<V, S>

> **PublicUnwrapSecretKeyWithPasswordImplementation**<`V`, `S`> = `Readonly`<{ `run`: (`paserk`, `password`, `limits`, `extractable`) => `Promise`<`S`>; `version`: `V`; }>

Low-level password-based secret key unwrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
