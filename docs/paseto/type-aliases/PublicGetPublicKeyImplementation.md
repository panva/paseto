# Type Alias: PublicGetPublicKeyImplementation\<V, P, S>

> **PublicGetPublicKeyImplementation**<`V`, `P`, `S`> = `Readonly`<{ `run`: (`key`) => `Promise`<`P`>; `version`: `V`; }>

Low-level public key derivation implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
