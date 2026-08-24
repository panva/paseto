# Function: SecretKeyToCryptoKey()

> **SecretKeyToCryptoKey**(`key`): `CryptoKey`

Returns the native Ed25519 private key retained by a built-in v4.public secret key.

This returns a key handle and does not export key material. A non-extractable key remains
non-extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | [`SecretKey`](../interfaces/SecretKey.md) | Built-in v4.public secret key |

## Returns

`CryptoKey`
