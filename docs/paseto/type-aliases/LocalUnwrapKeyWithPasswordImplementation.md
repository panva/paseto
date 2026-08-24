# Type Alias: LocalUnwrapKeyWithPasswordImplementation\<V, L>

> **LocalUnwrapKeyWithPasswordImplementation**<`V`, `L`> = `Readonly`<{ `run`: (`paserk`, `password`, `limits`, `extractable`) => `Promise`<`L`>; `version`: `V`; }>

Low-level password-based local key unwrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
