# Function: LocalEncrypt()

> **LocalEncrypt**<`V`, `L`>(`implementation`): [`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"Encrypt"`, <`C`, `Options`>(`key`, `claims`, `options?`) => `Promise`<`string`>>

Creates a composable local-token encryption capability factory.

## Type Parameters

| Type Parameter | Description |
| :------ | :------ |
| `V` *extends* [`Version`](../type-aliases/Version.md) | PASETO protocol version implemented by the capability |
| `L` *extends* [`Key`](../interfaces/Key.md) | Local key representation |

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `implementation` | [`LocalEncryptImplementation`](../type-aliases/LocalEncryptImplementation.md)<`V`, `L`> | Low-level local-token encryption implementation |

## Returns

[`CapabilityFactory`](../interfaces/CapabilityFactory.md)<`"local"`, `V`, `"Encrypt"`, <`C`, `Options`>(`key`, `claims`, `options?`) => `Promise`<`string`>>

## Remarks

The installed operation's `options` argument is `ProduceOptions<V>`.

## Installed Operation

The returned capability factory installs the following protocol method.

```text
Encrypt<C extends object>(key: L, claims: C, options?: ProduceOptions<V>): Promise<string>
```

`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.
