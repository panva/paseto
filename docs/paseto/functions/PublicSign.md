# Function: PublicSign()

> **PublicSign**<`V`, `S`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"Sign"`, <`C`, `Options`>(`key`, `claims`, `options?`) => `Promise`<`string`>>

Creates a composable public-token signing capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASETO protocol version implemented by the capability |
| `S` *extends* [`Key`](../interfaces/Key.md) | Secret signing key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`PublicSignImplementation`](../type-aliases/PublicSignImplementation.md)<`V`, `S`> | Low-level public-token signing implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"public"`, `V`, `"Sign"`, <`C`, `Options`>(`key`, `claims`, `options?`) => `Promise`<`string`>>

## Remarks

The installed operation's `options` argument is `ProduceOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
Sign<C extends object>(key: S, claims: C, options?: ProduceOptions<V>): Promise<string>
```

`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.
