# Function: SecretKeyToCryptoKey()

> **SecretKeyToCryptoKey**(`key`): `CryptoKey`

Returns the native RSA-PSS private key retained by a built-in v1.public secret key.

This returns a key handle and does not export key material. A non-extractable key remains
non-extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | [`SecretKey`](../interfaces/SecretKey.md) | Built-in v1.public secret key |

## Returns

`CryptoKey`
