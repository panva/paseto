/**
 * Built-in PASETO and PASERK v4.public capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v4/public
 * @category Public Implementations
 * @categoryDescription Token Operations
 * Factories for signing and verifying v4.public tokens.
 *
 * @categoryDescription Key Management
 * Verification and signing key types and factories for generating, importing, exporting, and
 * deriving keys.
 *
 * @categoryDescription CryptoKey Adapters
 * Adapters between built-in keys and runtime `CryptoKey` handles.
 *
 * @categoryDescription Key Wrapping
 * The wrapping key type and its generation, import, and export factories.
 */
import { PublicExportPublicKey, PublicExportSecretKey, PublicExportWrappingKey, PublicGenerateKeyPair, PublicGenerateWrappingKey, PublicGetPublicKey, PublicImportPublicKey, PublicImportSecretKey, PublicImportWrappingKey, PublicSign, PublicVerify, type CryptoKey, type Key } from 'paseto';
/**
 * Verification key used by the built-in v4.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v4.public';
    };
    readonly type: 'public';
    readonly version: 4;
    readonly kind: 'public';
}
/**
 * Wraps a native Ed25519 public key for use with the built-in v4.public capabilities.
 *
 * The key usages must include `verify`. The exact public-key instance is retained, including when
 * it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native Ed25519 public key
 */
export declare function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey>;
/**
 * Returns the native Ed25519 public key retained by a built-in v4.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v4.public key
 */
export declare function PublicKeyToCryptoKey(key: PublicKey): CryptoKey;
/**
 * Signing key used by the built-in v4.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v4.public';
    };
    readonly type: 'secret';
    readonly version: 4;
    readonly kind: 'secret';
}
/**
 * Wrapping key handled by the built-in k4 lifecycle capabilities.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
    readonly algorithm: {
        readonly name: 'PASERK k4.wrap';
    };
    readonly type: 'secret';
    readonly version: 4;
    readonly kind: 'wrapping';
}
/**
 * Wraps a native Ed25519 private key for use with the built-in v4.public capabilities.
 *
 * The key usages must include `sign`. The exact private-key instance is retained. Its public key is
 * obtained with `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native Ed25519 private key
 */
export declare function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey>;
/**
 * Returns the native Ed25519 private key retained by a built-in v4.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v4.public secret key
 */
export declare function SecretKeyToCryptoKey(key: SecretKey): CryptoKey;
/**
 * Built-in v4.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export declare const GenerateKeyPairFactory: ReturnType<typeof PublicGenerateKeyPair<4, PublicKey, SecretKey>>;
/**
 * Built-in v4.public token-signing capability factory.
 *
 * @category Token Operations
 */
export declare const SignFactory: ReturnType<typeof PublicSign<4, SecretKey>>;
/**
 * Built-in v4.public token-verification capability factory.
 *
 * @category Token Operations
 */
export declare const VerifyFactory: ReturnType<typeof PublicVerify<4, PublicKey>>;
/**
 * Built-in PASERK k4.public key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<4, PublicKey>>;
/**
 * Built-in PASERK k4.public key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<4, PublicKey>>;
/**
 * Built-in PASERK k4.secret key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<4, SecretKey>>;
/**
 * Built-in PASERK k4.secret key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<4, SecretKey>>;
/**
 * Built-in PASERK k4 public-key derivation capability factory.
 *
 * @category Key Management
 */
export declare const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<4, PublicKey, SecretKey>>;
/**
 * Built-in PASERK k4 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export declare const GenerateWrappingKeyFactory: ReturnType<typeof PublicGenerateWrappingKey<4, WrappingKey>>;
/**
 * Built-in PASERK k4 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export declare const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<4, WrappingKey>>;
/**
 * Built-in PASERK k4 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export declare const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<4, WrappingKey>>;
//# sourceMappingURL=public.d.ts.map