# Type Alias: LocalWrapKeyWithPasswordImplementation\<V, L>

> **LocalWrapKeyWithPasswordImplementation**<`V`, `L`> = `Readonly`<{ `run`: (`key`, `password`, `options`) => `Promise`<`` `k${V}.local-pw.${string}` ``>; `version`: `V`; }>

Low-level password-based local key wrapping implementation.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](Version.md) | Protocol version |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |
