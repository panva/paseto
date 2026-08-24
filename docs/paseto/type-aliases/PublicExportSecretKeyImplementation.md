# Type Alias: PublicExportSecretKeyImplementation\<V, S>

> **PublicExportSecretKeyImplementation**<`V`, `S`> = `Readonly`<{ `run`: (`key`) => `Promise`<`` `k${V}.secret.${string}` ``>; `version`: `V`; }>

Low-level secret signing key export implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
