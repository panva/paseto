# v4/public

Built-in PASETO and PASERK v4.public capability factories and CryptoKey adapters backed by
standard runtime APIs.

## Token Operations

Factories for signing and verifying v4.public tokens.

| Variable | Description |
| :------ | :------ |
| [SignFactory](variables/SignFactory.md) | Built-in v4.public token-signing capability factory. |
| [VerifyFactory](variables/VerifyFactory.md) | Built-in v4.public token-verification capability factory. |

## Key Management

Verification and signing key types and factories for generating, importing, exporting, and
deriving keys.

| Name | Description |
| :------ | :------ |
| [PublicKey](interfaces/PublicKey.md) | Verification key used by the built-in v4.public implementations. |
| [SecretKey](interfaces/SecretKey.md) | Signing key used by the built-in v4.public implementations. |
| [ExportPublicKeyFactory](variables/ExportPublicKeyFactory.md) | Built-in PASERK k4.public key-export capability factory. |
| [ExportSecretKeyFactory](variables/ExportSecretKeyFactory.md) | Built-in PASERK k4.secret key-export capability factory. |
| [GenerateKeyPairFactory](variables/GenerateKeyPairFactory.md) | Built-in v4.public signing-key-pair generation capability factory. |
| [GetPublicKeyFactory](variables/GetPublicKeyFactory.md) | Built-in PASERK k4 public-key derivation capability factory. |
| [ImportPublicKeyFactory](variables/ImportPublicKeyFactory.md) | Built-in PASERK k4.public key-import capability factory. |
| [ImportSecretKeyFactory](variables/ImportSecretKeyFactory.md) | Built-in PASERK k4.secret key-import capability factory. |

## CryptoKey Adapters

Adapters between built-in keys and runtime `CryptoKey` handles.

| Function | Description |
| :------ | :------ |
| [PublicKeyFromCryptoKey](functions/PublicKeyFromCryptoKey.md) | Wraps a native Ed25519 public key for use with the built-in v4.public capabilities. |
| [PublicKeyToCryptoKey](functions/PublicKeyToCryptoKey.md) | Returns the native Ed25519 public key retained by a built-in v4.public key. |
| [SecretKeyFromCryptoKey](functions/SecretKeyFromCryptoKey.md) | Wraps a native Ed25519 private key for use with the built-in v4.public capabilities. |
| [SecretKeyToCryptoKey](functions/SecretKeyToCryptoKey.md) | Returns the native Ed25519 private key retained by a built-in v4.public secret key. |

## Key Wrapping

The wrapping key type and its generation, import, and export factories.

| Name | Description |
| :------ | :------ |
| [WrappingKey](interfaces/WrappingKey.md) | Wrapping key handled by the built-in k4 lifecycle capabilities. |
| [ExportWrappingKeyFactory](variables/ExportWrappingKeyFactory.md) | Built-in PASERK k4 wrapping-key export capability factory. |
| [GenerateWrappingKeyFactory](variables/GenerateWrappingKeyFactory.md) | Built-in PASERK k4 wrapping-key generation capability factory. |
| [ImportWrappingKeyFactory](variables/ImportWrappingKeyFactory.md) | Built-in PASERK k4 wrapping-key import capability factory. |
