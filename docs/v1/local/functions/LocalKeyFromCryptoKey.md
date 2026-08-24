# Function: LocalKeyFromCryptoKey()

> **LocalKeyFromCryptoKey**(`key`): [`LocalKey`](../interfaces/LocalKey.md)

Wraps a native HKDF key for use with the built-in v1.local capabilities.

The key must be a secret `CryptoKey` whose usages include `deriveBits`. The exact key instance is
retained, including when it is non-extractable.

## Parameters

| Parameter | Type | Description |
| :------ | :------ | :------ |
| `key` | `CryptoKey` | Native HKDF key |

## Returns

[`LocalKey`](../interfaces/LocalKey.md)
