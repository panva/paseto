# Type Alias: PublicExportPublicKeyImplementation\<V, P>

> **PublicExportPublicKeyImplementation**<`V`, `P`> = `Readonly`<{ `run`: (`key`) => `Promise`<`` `k${V}.public.${string}` ``>; `version`: `V`; }>

Low-level public verification key export implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `P` *extends* [`Key`](../interfaces/Key.md) | Public verification key representation |
