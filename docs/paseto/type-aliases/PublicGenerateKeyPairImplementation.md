# Type Alias: PublicGenerateKeyPairImplementation\<V, P, S>

> **PublicGenerateKeyPairImplementation**<`V`, `P`, `S`> = `Readonly`<{ `run`: (`extractable`) => `Promise`<[`KeyPair`](../interfaces/KeyPair.md)<`P`, `S`>>; `version`: `V`; }>

Low-level public-purpose key pair generation implementation.

`extractable` applies to the secret signing key. Public verification keys are always extractable.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |
