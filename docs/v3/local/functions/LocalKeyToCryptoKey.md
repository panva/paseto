# Function: LocalKeyToCryptoKey()

> **LocalKeyToCryptoKey**(`key`): `CryptoKey`

Returns the native HKDF key retained by a built-in v3.local key.

This returns a key handle and does not export key material. A non-extractable key remains
non-extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | [`LocalKey`](../interfaces/LocalKey.md) | Built-in v3.local key |

## Returns

`CryptoKey`
