# v3/local

Built-in PASETO and PASERK v3.local capability factories and CryptoKey adapters backed by
standard runtime APIs.

## Token Operations

Factories for encrypting and decrypting v3.local tokens.

| Variable | Description |
| :------ | :------ |
| [DecryptFactory](variables/DecryptFactory.md) | Built-in v3.local token-decryption capability factory. |
| [EncryptFactory](variables/EncryptFactory.md) | Built-in v3.local token-encryption capability factory. |

## Key Management

The local key type and factories for generating, importing, exporting, and identifying local
keys.

| Name | Description |
| :------ | :------ |
| [LocalKey](interfaces/LocalKey.md) | Key used by the built-in v3.local implementations. |
| [ExportKeyFactory](variables/ExportKeyFactory.md) | Built-in PASERK k3.local key-export capability factory. |
| [GenerateKeyFactory](variables/GenerateKeyFactory.md) | Built-in v3.local symmetric-key generation capability factory. |
| [ImportKeyFactory](variables/ImportKeyFactory.md) | Built-in PASERK k3.local key-import capability factory. |
| [KeyIDFactory](variables/KeyIDFactory.md) | Built-in PASERK k3.lid identifier capability factory. |

## CryptoKey Adapters

Adapters between native HKDF `CryptoKey` instances and built-in local keys.

| Function | Description |
| :------ | :------ |
| [LocalKeyFromCryptoKey](functions/LocalKeyFromCryptoKey.md) | Wraps a native HKDF key for use with the built-in v3.local capabilities. |
| [LocalKeyToCryptoKey](functions/LocalKeyToCryptoKey.md) | Returns the native HKDF key retained by a built-in v3.local key. |

## Key Wrapping

The wrapping key type and factories for managing wrapping keys and wrapping local keys with PIE.

| Name | Description |
| :------ | :------ |
| [WrappingKey](interfaces/WrappingKey.md) | Wrapping key used by the built-in k3.local-wrap.pie implementation. |
| [ExportWrappingKeyFactory](variables/ExportWrappingKeyFactory.md) | Built-in PASERK k3 wrapping-key export capability factory. |
| [GenerateWrappingKeyFactory](variables/GenerateWrappingKeyFactory.md) | Built-in PASERK k3 wrapping-key generation capability factory. |
| [ImportWrappingKeyFactory](variables/ImportWrappingKeyFactory.md) | Built-in PASERK k3 wrapping-key import capability factory. |
| [UnwrapKeyFactory](variables/UnwrapKeyFactory.md) | Built-in PASERK k3.local-wrap.pie unwrapping capability factory. |
| [WrapKeyFactory](variables/WrapKeyFactory.md) | Built-in PASERK k3.local-wrap.pie wrapping capability factory. |

## Password-Based Key Wrapping

Factories for password-based local-key wrapping and unwrapping.

| Variable | Description |
| :------ | :------ |
| [UnwrapKeyWithPasswordFactory](variables/UnwrapKeyWithPasswordFactory.md) | Built-in PASERK k3.local-pw unwrapping capability factory. |
| [WrapKeyWithPasswordFactory](variables/WrapKeyWithPasswordFactory.md) | Built-in PASERK k3.local-pw wrapping capability factory. |

## Key Sealing

Sealing key types and factories for managing recipient keys and sealing local keys.

| Name | Description |
| :------ | :------ |
| [SealingPublicKey](interfaces/SealingPublicKey.md) | Public recipient key used by the built-in k3.seal implementation. |
| [SealingSecretKey](interfaces/SealingSecretKey.md) | Secret recipient key used by the built-in k3.seal implementation. |
| [ExportSealingPublicKeyFactory](variables/ExportSealingPublicKeyFactory.md) | Built-in PASERK k3.seal public-key export capability factory. |
| [ExportSealingSecretKeyFactory](variables/ExportSealingSecretKeyFactory.md) | Built-in PASERK k3.seal secret-key export capability factory. |
| [GenerateSealingKeyPairFactory](variables/GenerateSealingKeyPairFactory.md) | Built-in PASERK k3.seal recipient key-pair generation capability factory. |
| [ImportSealingPublicKeyFactory](variables/ImportSealingPublicKeyFactory.md) | Built-in PASERK k3.seal public-key import capability factory. |
| [ImportSealingSecretKeyFactory](variables/ImportSealingSecretKeyFactory.md) | Built-in PASERK k3.seal secret-key import capability factory. |
| [SealKeyFactory](variables/SealKeyFactory.md) | Built-in PASERK k3.seal key-sealing capability factory. |
| [UnsealKeyFactory](variables/UnsealKeyFactory.md) | Built-in PASERK k3.seal key-unsealing capability factory. |
