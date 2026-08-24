# Type Alias: PublicWrapSecretKeyWithPasswordImplementation\<V, S>

> **PublicWrapSecretKeyWithPasswordImplementation**<`V`, `S`> = `Readonly`<{ `run`: (`key`, `password`, `options`) => `Promise`<`` `k${V}.secret-pw.${string}` ``>; `version`: `V`; }>

Low-level password-based secret key wrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
