# paseto

Protocol-neutral PASETO and PASERK composition APIs for JavaScript runtimes.

## Protocol Composition

Version and purpose metadata plus the factories and types used to compose selected capabilities.

| Name | Description |
| :------ | :------ |
| [CapabilityFactory](interfaces/CapabilityFactory.md) | A protocol-operation factory returned by a root operation creator and recognized by protocol constructors. Its structural callable type permits composition across package copies; runtime recognition is not a provenance guarantee. |
| [LocalCapabilityFactory](type-aliases/LocalCapabilityFactory.md) | One local-purpose capability factory accepted by [LocalProtocol](variables/LocalProtocol.md). |
| [LocalOperation](type-aliases/LocalOperation.md) | Operation names supported by local-purpose protocol composition. |
| [LocalProtocolFactories](type-aliases/LocalProtocolFactories.md) | A non-empty tuple of local-purpose capability factories. |
| [LocalProtocolInstance](type-aliases/LocalProtocolInstance.md) | A local protocol exposing exactly the selected capabilities. |
| [PublicCapabilityFactory](type-aliases/PublicCapabilityFactory.md) | One public-purpose capability factory accepted by [PublicProtocol](variables/PublicProtocol.md). |
| [PublicOperation](type-aliases/PublicOperation.md) | Operation names supported by public-purpose protocol composition. |
| [PublicProtocolFactories](type-aliases/PublicProtocolFactories.md) | A non-empty tuple of public-purpose capability factories. |
| [PublicProtocolInstance](type-aliases/PublicProtocolInstance.md) | A public protocol exposing exactly the selected capabilities. |
| [Purpose](type-aliases/Purpose.md) | Purpose discriminator carried by every capability. |
| [Version](type-aliases/Version.md) | Supported PASETO and PASERK protocol versions. |
| [LocalProtocol](variables/LocalProtocol.md) | Composes selected local-purpose capabilities into a same-version protocol instance. |
| [PublicProtocol](variables/PublicProtocol.md) | Composes selected public-purpose capabilities into a same-version protocol instance. |

## Local Token Operations

Low-level contracts and creators for local-token encryption and decryption.

| Name | Description |
| :------ | :------ |
| [LocalDecryptImplementation](type-aliases/LocalDecryptImplementation.md) | Low-level local token decryption implementation. |
| [LocalEncryptImplementation](type-aliases/LocalEncryptImplementation.md) | Low-level local token encryption implementation. |
| [LocalDecrypt](functions/LocalDecrypt.md) | Creates a composable local-token decryption capability factory. |
| [LocalEncrypt](functions/LocalEncrypt.md) | Creates a composable local-token encryption capability factory. |

## Local Key Management

Contracts and creators for generating, importing, exporting, and identifying local keys.

| Name | Description |
| :------ | :------ |
| [LocalExportKeyImplementation](type-aliases/LocalExportKeyImplementation.md) | Low-level local key export implementation. |
| [LocalGenerateKeyImplementation](type-aliases/LocalGenerateKeyImplementation.md) | Low-level local key generation implementation. |
| [LocalImportKeyImplementation](type-aliases/LocalImportKeyImplementation.md) | Low-level local key import implementation. |
| [LocalKeyIDImplementation](type-aliases/LocalKeyIDImplementation.md) | Low-level local key identifier implementation. |
| [LocalExportKey](functions/LocalExportKey.md) | Creates a composable local PASERK export capability factory. |
| [LocalGenerateKey](functions/LocalGenerateKey.md) | Creates a composable local key-generation capability factory. |
| [LocalImportKey](functions/LocalImportKey.md) | Creates a composable local PASERK import capability factory. |
| [LocalKeyID](functions/LocalKeyID.md) | Creates a composable local PASERK ID capability factory. |

## Local Key Wrapping

Contracts and creators for local wrapping-key management and symmetric key wrapping.

| Name | Description |
| :------ | :------ |
| [LocalExportWrappingKeyImplementation](type-aliases/LocalExportWrappingKeyImplementation.md) | Low-level wrapping key export implementation for local-purpose keys. |
| [LocalGenerateWrappingKeyImplementation](type-aliases/LocalGenerateWrappingKeyImplementation.md) | Low-level wrapping key generation implementation for local-purpose keys. |
| [LocalImportWrappingKeyImplementation](type-aliases/LocalImportWrappingKeyImplementation.md) | Low-level wrapping key import implementation for local-purpose keys. |
| [LocalUnwrapKeyImplementation](type-aliases/LocalUnwrapKeyImplementation.md) | Low-level local key unwrapping implementation. |
| [LocalWrapKeyImplementation](type-aliases/LocalWrapKeyImplementation.md) | Low-level local key wrapping implementation. |
| [LocalExportWrappingKey](functions/LocalExportWrappingKey.md) | Creates a composable local wrapping-key export capability factory. |
| [LocalGenerateWrappingKey](functions/LocalGenerateWrappingKey.md) | Creates a composable local wrapping-key generation capability factory. |
| [LocalImportWrappingKey](functions/LocalImportWrappingKey.md) | Creates a composable local wrapping-key import capability factory. |
| [LocalUnwrapKey](functions/LocalUnwrapKey.md) | Creates a composable local key-unwrapping capability factory. |
| [LocalWrapKey](functions/LocalWrapKey.md) | Creates a composable local key-wrapping capability factory. |

## Public Token Operations

Low-level contracts and creators for public-token signing and verification.

| Name | Description |
| :------ | :------ |
| [PublicSignImplementation](type-aliases/PublicSignImplementation.md) | Low-level public token signing implementation. |
| [PublicVerifyImplementation](type-aliases/PublicVerifyImplementation.md) | Low-level public token verification implementation. |
| [PublicSign](functions/PublicSign.md) | Creates a composable public-token signing capability factory. |
| [PublicVerify](functions/PublicVerify.md) | Creates a composable public-token verification capability factory. |

## Public Key Management

Contracts and creators for managing signing and verification keys and their identifiers.

| Name | Description |
| :------ | :------ |
| [PublicExportPublicKeyImplementation](type-aliases/PublicExportPublicKeyImplementation.md) | Low-level public verification key export implementation. |
| [PublicExportSecretKeyImplementation](type-aliases/PublicExportSecretKeyImplementation.md) | Low-level secret signing key export implementation. |
| [PublicGenerateKeyPairImplementation](type-aliases/PublicGenerateKeyPairImplementation.md) | Low-level public-purpose key pair generation implementation. |
| [PublicGetPublicKeyImplementation](type-aliases/PublicGetPublicKeyImplementation.md) | Low-level public key derivation implementation. |
| [PublicImportPublicKeyImplementation](type-aliases/PublicImportPublicKeyImplementation.md) | Low-level public verification key import implementation. |
| [PublicImportSecretKeyImplementation](type-aliases/PublicImportSecretKeyImplementation.md) | Low-level secret signing key import implementation. |
| [PublicKeyIDImplementation](type-aliases/PublicKeyIDImplementation.md) | Low-level public key identifier implementation. |
| [SecretKeyIDImplementation](type-aliases/SecretKeyIDImplementation.md) | Low-level secret key identifier implementation. |
| [PublicExportPublicKey](functions/PublicExportPublicKey.md) | Creates a composable public PASERK export capability factory. |
| [PublicExportSecretKey](functions/PublicExportSecretKey.md) | Creates a composable secret PASERK export capability factory. |
| [PublicGenerateKeyPair](functions/PublicGenerateKeyPair.md) | Creates a composable public key-pair generation capability factory. |
| [PublicGetPublicKey](functions/PublicGetPublicKey.md) | Creates a composable public-key derivation capability factory. |
| [PublicImportPublicKey](functions/PublicImportPublicKey.md) | Creates a composable public PASERK import capability factory. |
| [PublicImportSecretKey](functions/PublicImportSecretKey.md) | Creates a composable secret PASERK import capability factory. |
| [PublicKeyID](functions/PublicKeyID.md) | Creates a composable public PASERK ID capability factory. |
| [SecretKeyID](functions/SecretKeyID.md) | Creates a composable secret PASERK ID capability factory. |

## Public Key Wrapping

Contracts and creators for wrapping-key management and symmetric secret-key wrapping.

| Name | Description |
| :------ | :------ |
| [PublicExportWrappingKeyImplementation](type-aliases/PublicExportWrappingKeyImplementation.md) | Low-level wrapping key export implementation for public-purpose keys. |
| [PublicGenerateWrappingKeyImplementation](type-aliases/PublicGenerateWrappingKeyImplementation.md) | Low-level wrapping key generation implementation for public-purpose keys. |
| [PublicImportWrappingKeyImplementation](type-aliases/PublicImportWrappingKeyImplementation.md) | Low-level wrapping key import implementation for public-purpose keys. |
| [PublicUnwrapSecretKeyImplementation](type-aliases/PublicUnwrapSecretKeyImplementation.md) | Low-level secret key unwrapping implementation. |
| [PublicWrapSecretKeyImplementation](type-aliases/PublicWrapSecretKeyImplementation.md) | Low-level secret key wrapping implementation. |
| [PublicExportWrappingKey](functions/PublicExportWrappingKey.md) | Creates a composable wrapping-key export capability factory for public-purpose keys. |
| [PublicGenerateWrappingKey](functions/PublicGenerateWrappingKey.md) | Creates a composable wrapping-key generation capability factory for public-purpose keys. |
| [PublicImportWrappingKey](functions/PublicImportWrappingKey.md) | Creates a composable wrapping-key import capability factory for public-purpose keys. |
| [PublicUnwrapSecretKey](functions/PublicUnwrapSecretKey.md) | Creates a composable secret key-unwrapping capability factory. |
| [PublicWrapSecretKey](functions/PublicWrapSecretKey.md) | Creates a composable secret key-wrapping capability factory. |

## Password-Based Key Wrapping

Argon2id contracts, options, and creators for password-protected local and secret keys.

| Name | Description |
| :------ | :------ |
| [Argon2id](interfaces/Argon2id.md) | Replaceable Argon2id implementation contract. |
| [Argon2idParameters](interfaces/Argon2idParameters.md) | Parameters for an Argon2id implementation. Memory is expressed in bytes. |
| [Argon2idFactory](type-aliases/Argon2idFactory.md) | Factory function for an Argon2id implementation. |
| [LocalUnwrapKeyWithPasswordImplementation](type-aliases/LocalUnwrapKeyWithPasswordImplementation.md) | Low-level password-based local key unwrapping implementation. |
| [LocalWrapKeyWithPasswordImplementation](type-aliases/LocalWrapKeyWithPasswordImplementation.md) | Low-level password-based local key wrapping implementation. |
| [PasswordUnwrapLimits](type-aliases/PasswordUnwrapLimits.md) | Resource limits passed to a low-level password-unwrapping implementation. V1 and v3 receive `maxIterations`; v2 and v4 receive `maxMemory`, `maxPasses`, and `maxParallelism`. |
| [PasswordUnwrapOptions](type-aliases/PasswordUnwrapOptions.md) | Options used when unwrapping a password-protected PASERK. All versions support `extractable`; v1 and v3 support `maxIterations`, while v2 and v4 support `maxMemory`, `maxPasses`, and `maxParallelism`. |
| [PasswordWrapOptions](type-aliases/PasswordWrapOptions.md) | Options used when password-wrapping a PASERK. V1 and v3 use PBKDF2 `iterations`; v2 and v4 use Argon2id `memory`, `passes`, and `parallelism`. |
| [PublicUnwrapSecretKeyWithPasswordImplementation](type-aliases/PublicUnwrapSecretKeyWithPasswordImplementation.md) | Low-level password-based secret key unwrapping implementation. |
| [PublicWrapSecretKeyWithPasswordImplementation](type-aliases/PublicWrapSecretKeyWithPasswordImplementation.md) | Low-level password-based secret key wrapping implementation. |
| [KDF\_ARGON2ID](variables/KDF_ARGON2ID.md) | Web Cryptography Argon2id implementation. |
| [LocalUnwrapKeyWithPassword](functions/LocalUnwrapKeyWithPassword.md) | Creates a composable password-based local key-unwrapping capability factory. |
| [LocalWrapKeyWithPassword](functions/LocalWrapKeyWithPassword.md) | Creates a composable password-based local key-wrapping capability factory. |
| [PublicUnwrapSecretKeyWithPassword](functions/PublicUnwrapSecretKeyWithPassword.md) | Creates a composable password-based secret key-unwrapping capability factory. |
| [PublicWrapSecretKeyWithPassword](functions/PublicWrapSecretKeyWithPassword.md) | Creates a composable password-based secret key-wrapping capability factory. |

## Key Sealing

Contracts and creators for sealing-key management and asymmetric local-key protection.

| Name | Description |
| :------ | :------ |
| [LocalExportSealingPublicKeyImplementation](type-aliases/LocalExportSealingPublicKeyImplementation.md) | Low-level sealing public key export implementation. |
| [LocalExportSealingSecretKeyImplementation](type-aliases/LocalExportSealingSecretKeyImplementation.md) | Low-level sealing secret key export implementation. |
| [LocalGenerateSealingKeyPairImplementation](type-aliases/LocalGenerateSealingKeyPairImplementation.md) | Low-level sealing key pair generation implementation. |
| [LocalImportSealingPublicKeyImplementation](type-aliases/LocalImportSealingPublicKeyImplementation.md) | Low-level sealing public key import implementation. |
| [LocalImportSealingSecretKeyImplementation](type-aliases/LocalImportSealingSecretKeyImplementation.md) | Low-level sealing secret key import implementation. |
| [LocalSealKeyImplementation](type-aliases/LocalSealKeyImplementation.md) | Low-level local key sealing implementation. |
| [LocalUnsealKeyImplementation](type-aliases/LocalUnsealKeyImplementation.md) | Low-level local key unsealing implementation. |
| [LocalExportSealingPublicKey](functions/LocalExportSealingPublicKey.md) | Creates a composable sealing public-key export capability factory. |
| [LocalExportSealingSecretKey](functions/LocalExportSealingSecretKey.md) | Creates a composable sealing secret-key export capability factory. |
| [LocalGenerateSealingKeyPair](functions/LocalGenerateSealingKeyPair.md) | Creates a composable sealing key-pair generation capability factory. |
| [LocalImportSealingPublicKey](functions/LocalImportSealingPublicKey.md) | Creates a composable sealing public-key import capability factory. |
| [LocalImportSealingSecretKey](functions/LocalImportSealingSecretKey.md) | Creates a composable sealing secret-key import capability factory. |
| [LocalSealKey](functions/LocalSealKey.md) | Creates a composable local key-sealing capability factory. |
| [LocalUnsealKey](functions/LocalUnsealKey.md) | Creates a composable local key-unsealing capability factory. |

## Tokens and Claims

Claim values, token production and consumption options, and authenticated token results.

| Name | Description |
| :------ | :------ |
| [TokenResult](interfaces/TokenResult.md) | A successfully authenticated PASETO. |
| [Claims](type-aliases/Claims.md) | A decoded PASETO claims object. |
| [ConsumeOptions](type-aliases/ConsumeOptions.md) | Options used when consuming a token. All versions support `footer`, `now`, `clockTolerance`, `allowNonExpiring`, `maxTokenAge`, `audience`, `issuer`, `subject`, `tokenIdentifier`, and `requiredClaims`; only v3 and v4 support `implicitAssertion`. |
| [JsonValue](type-aliases/JsonValue.md) | A value accepted in a PASETO claims object. |
| [ProduceOptions](type-aliases/ProduceOptions.md) | Options used when creating a token. All versions support `footer`, `now`, `addIssuedAt`, `expiresIn`, and `nonExpiring`; only v3 and v4 support `implicitAssertion`. |

## Keys

Portable key representations, key pairs, and secret-key extractability options.

| Name | Description |
| :------ | :------ |
| [Key](interfaces/Key.md) | Minimal key representation understood by protocol implementations. |
| [KeyOptions](interfaces/KeyOptions.md) | Options controlling secret-key extractability. |
| [KeyPair](interfaces/KeyPair.md) | A public and secret key pair returned by a key-pair generation capability. |
| [CryptoKey](type-aliases/CryptoKey.md) | A Web Cryptography key as declared by the host runtime. |

## PASERK Serializations

Typed PASERK serializations and the serialization inputs accepted by key identifiers.

| Type Alias | Description |
| :------ | :------ |
| [LocalIdPASERK](type-aliases/LocalIdPASERK.md) | A local-key identifier PASERK. |
| [LocalKeyIDInput](type-aliases/LocalKeyIDInput.md) | A PASERK serialization accepted when deriving a local key identifier. |
| [LocalPASERK](type-aliases/LocalPASERK.md) | A plaintext symmetric-key PASERK. |
| [PasswordWrappedLocalPASERK](type-aliases/PasswordWrappedLocalPASERK.md) | A password-wrapped local-key PASERK. |
| [PasswordWrappedSecretPASERK](type-aliases/PasswordWrappedSecretPASERK.md) | A password-wrapped secret-key PASERK. |
| [PublicIdPASERK](type-aliases/PublicIdPASERK.md) | A public-key identifier PASERK. |
| [PublicPASERK](type-aliases/PublicPASERK.md) | A plaintext public-key PASERK. |
| [SealedLocalPASERK](type-aliases/SealedLocalPASERK.md) | An asymmetrically sealed local-key PASERK. |
| [SecretIdPASERK](type-aliases/SecretIdPASERK.md) | A secret-key identifier PASERK. |
| [SecretKeyIDInput](type-aliases/SecretKeyIDInput.md) | A PASERK serialization accepted when deriving a secret key identifier. |
| [SecretPASERK](type-aliases/SecretPASERK.md) | A plaintext secret-key PASERK. |
| [WrappedLocalPASERK](type-aliases/WrappedLocalPASERK.md) | A symmetrically wrapped local-key PASERK. |
| [WrappedSecretPASERK](type-aliases/WrappedSecretPASERK.md) | A symmetrically wrapped secret-key PASERK. |

## Utilities

Protocol-independent helpers for pre-authentication encoding and footer inspection.

| Function | Description |
| :------ | :------ |
| [InspectFooter](functions/InspectFooter.md) | Extracts a token footer without authenticating it. |
| [PAE](functions/PAE.md) | Pre-Authentication Encoding (PAE). |

## Errors

Stable error codes and error classes produced by the protocol APIs.

| Name | Description |
| :------ | :------ |
| [ClaimValidationError](classes/ClaimValidationError.md) | An authenticated token contains claims that fail validation. |
| [InvalidKeyError](classes/InvalidKeyError.md) | The key is malformed, unavailable for an operation, or belongs to another protocol tuple. |
| [InvalidPASERKError](classes/InvalidPASERKError.md) | The PASERK is malformed or failed authentication. |
| [InvalidTokenError](classes/InvalidTokenError.md) | The token is malformed or failed authentication. |
| [PasetoError](classes/PasetoError.md) | Base class for errors produced by this module. |
| [UnsupportedAlgorithmError](classes/UnsupportedAlgorithmError.md) | The current runtime does not provide a required cryptographic primitive. |
| [PasetoErrorCode](type-aliases/PasetoErrorCode.md) | Stable machine-readable codes used by errors produced by this module. |
