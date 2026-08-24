# Type Alias: PublicImportSecretKeyImplementation\<V, S>

> **PublicImportSecretKeyImplementation**<`V`, `S`> = `Readonly`<{ `run`: (`paserk`, `extractable`) => `Promise`<`S`>; `version`: `V`; }>

Low-level secret signing key import implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
