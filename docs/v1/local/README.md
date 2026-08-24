# v1/local

Built-in PASETO and PASERK v1.local capability factories and CryptoKey adapters backed by
standard runtime APIs.

## Token Operations

Factories for encrypting and decrypting v1.local tokens.

| Variable | Description |
| :------ | :------ |
| [DecryptFactory](variables/DecryptFactory.md) | Built-in v1.local token-decryption capability factory. |
| [EncryptFactory](variables/EncryptFactory.md) | Built-in v1.local token-encryption capability factory. |

## Key Management

The local key type and factories for generating, importing, exporting, and identifying local
keys.

| Name | Description |
| :------ | :------ |
| [LocalKey](interfaces/LocalKey.md) | Key used by the built-in v1.local implementations. |
| [ExportKeyFactory](variables/ExportKeyFactory.md) | Built-in PASERK k1.local key-export capability factory. |
| [GenerateKeyFactory](variables/GenerateKeyFactory.md) | Built-in v1.local symmetric-key generation capability factory. |
| [ImportKeyFactory](variables/ImportKeyFactory.md) | Built-in PASERK k1.local key-import capability factory. |
| [KeyIDFactory](variables/KeyIDFactory.md) | Built-in PASERK k1.lid identifier capability factory. |

## CryptoKey Adapters

Adapters between native HKDF `CryptoKey` instances and built-in local keys.

| Function | Description |
| :------ | :------ |
| [LocalKeyFromCryptoKey](functions/LocalKeyFromCryptoKey.md) | Wraps a native HKDF key for use with the built-in v1.local capabilities. |
| [LocalKeyToCryptoKey](functions/LocalKeyToCryptoKey.md) | Returns the native HKDF key retained by a built-in v1.local key. |

## Key Wrapping

The wrapping key type and factories for managing wrapping keys and wrapping local keys with PIE.

| Name | Description |
| :------ | :------ |
| [WrappingKey](interfaces/WrappingKey.md) | Wrapping key used by the built-in k1.local-wrap.pie implementation. |
| [ExportWrappingKeyFactory](variables/ExportWrappingKeyFactory.md) | Built-in PASERK k1 wrapping-key export capability factory. |
| [GenerateWrappingKeyFactory](variables/GenerateWrappingKeyFactory.md) | Built-in PASERK k1 wrapping-key generation capability factory. |
| [ImportWrappingKeyFactory](variables/ImportWrappingKeyFactory.md) | Built-in PASERK k1 wrapping-key import capability factory. |
| [UnwrapKeyFactory](variables/UnwrapKeyFactory.md) | Built-in PASERK k1.local-wrap.pie unwrapping capability factory. |
| [WrapKeyFactory](variables/WrapKeyFactory.md) | Built-in PASERK k1.local-wrap.pie wrapping capability factory. |

## Password-Based Key Wrapping

Factories for password-based local-key wrapping and unwrapping.

| Variable | Description |
| :------ | :------ |
| [UnwrapKeyWithPasswordFactory](variables/UnwrapKeyWithPasswordFactory.md) | Built-in PASERK k1.local-pw unwrapping capability factory. |
| [WrapKeyWithPasswordFactory](variables/WrapKeyWithPasswordFactory.md) | Built-in PASERK k1.local-pw wrapping capability factory. |
