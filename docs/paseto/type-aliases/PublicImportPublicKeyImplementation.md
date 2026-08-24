# Type Alias: PublicImportPublicKeyImplementation\<V, P>

> **PublicImportPublicKeyImplementation**<`V`, `P`> = `Readonly`<{ `run`: (`paserk`) => `Promise`<`P`>; `version`: `V`; }>

Low-level public verification key import implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |
