# v3/public

Built-in PASETO and PASERK v3.public capability factories and CryptoKey adapters backed by
standard runtime APIs.

## Token Operations

Factories for signing and verifying v3.public tokens.

| Variable | Description |
| :------ | :------ |
| [SignFactory](variables/SignFactory.md) | Built-in v3.public token-signing capability factory. |
| [VerifyFactory](variables/VerifyFactory.md) | Built-in v3.public token-verification capability factory. |

## Key Management

Verification and signing key types and factories for generating, importing, exporting, deriving,
and identifying keys.

| Name | Description |
| :------ | :------ |
| [PublicKey](interfaces/PublicKey.md) | Verification key used by the built-in v3.public implementations. |
| [SecretKey](interfaces/SecretKey.md) | Signing key used by the built-in v3.public implementations. |
| [ExportPublicKeyFactory](variables/ExportPublicKeyFactory.md) | Built-in PASERK k3.public key-export capability factory. |
| [ExportSecretKeyFactory](variables/ExportSecretKeyFactory.md) | Built-in PASERK k3.secret key-export capability factory. |
| [GenerateKeyPairFactory](variables/GenerateKeyPairFactory.md) | Built-in v3.public signing-key-pair generation capability factory. |
| [GetPublicKeyFactory](variables/GetPublicKeyFactory.md) | Built-in PASERK k3 public-key derivation capability factory. |
| [ImportPublicKeyFactory](variables/ImportPublicKeyFactory.md) | Built-in PASERK k3.public key-import capability factory. |
| [ImportSecretKeyFactory](variables/ImportSecretKeyFactory.md) | Built-in PASERK k3.secret key-import capability factory. |
| [PublicKeyIDFactory](variables/PublicKeyIDFactory.md) | Built-in PASERK k3.pid identifier capability factory. |
| [SecretKeyIDFactory](variables/SecretKeyIDFactory.md) | Built-in PASERK k3.sid identifier capability factory. |

## CryptoKey Adapters

Adapters between built-in keys and runtime `CryptoKey` handles.

| Function | Description |
| :------ | :------ |
| [PublicKeyFromCryptoKey](functions/PublicKeyFromCryptoKey.md) | Wraps a native ECDSA P-384 public key for use with the built-in v3.public capabilities. |
| [PublicKeyToCryptoKey](functions/PublicKeyToCryptoKey.md) | Returns the native ECDSA P-384 public key retained by a built-in v3.public key. |
| [SecretKeyFromCryptoKey](functions/SecretKeyFromCryptoKey.md) | Wraps a native ECDSA P-384 private key for use with the built-in v3.public capabilities. |
| [SecretKeyToCryptoKey](functions/SecretKeyToCryptoKey.md) | Returns the native ECDSA private key retained by a built-in v3.public secret key. |

## Key Wrapping

The wrapping key type and factories for managing wrapping keys and wrapping secret keys with PIE.

| Name | Description |
| :------ | :------ |
| [WrappingKey](interfaces/WrappingKey.md) | Wrapping key used by the built-in k3.secret-wrap.pie implementation. |
| [ExportWrappingKeyFactory](variables/ExportWrappingKeyFactory.md) | Built-in PASERK k3 wrapping-key export capability factory. |
| [GenerateWrappingKeyFactory](variables/GenerateWrappingKeyFactory.md) | Built-in PASERK k3 wrapping-key generation capability factory. |
| [ImportWrappingKeyFactory](variables/ImportWrappingKeyFactory.md) | Built-in PASERK k3 wrapping-key import capability factory. |
| [UnwrapSecretKeyFactory](variables/UnwrapSecretKeyFactory.md) | Built-in PASERK k3.secret-wrap.pie unwrapping capability factory. |
| [WrapSecretKeyFactory](variables/WrapSecretKeyFactory.md) | Built-in PASERK k3.secret-wrap.pie wrapping capability factory. |

## Password-Based Key Wrapping

Factories for password-based secret-key wrapping and unwrapping.

| Variable | Description |
| :------ | :------ |
| [UnwrapSecretKeyWithPasswordFactory](variables/UnwrapSecretKeyWithPasswordFactory.md) | Built-in PASERK k3.secret-pw unwrapping capability factory. |
| [WrapSecretKeyWithPasswordFactory](variables/WrapSecretKeyWithPasswordFactory.md) | Built-in PASERK k3.secret-pw wrapping capability factory. |
