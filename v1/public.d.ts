/**
 * Built-in PASETO and PASERK v1.public capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v1/public
 * @category Public Implementations
 * @categoryDescription Token Operations
 * Factories for signing and verifying v1.public tokens.
 *
 * @categoryDescription Key Management
 * Verification and signing key types and factories for generating, importing, exporting, deriving,
 * and identifying keys.
 *
 * @categoryDescription CryptoKey Adapters
 * Adapters between built-in keys and runtime `CryptoKey` handles.
 *
 * @categoryDescription Key Wrapping
 * The wrapping key type and factories for managing wrapping keys and wrapping secret keys with PIE.
 *
 * @categoryDescription Password-Based Key Wrapping
 * Factories for password-based secret-key wrapping and unwrapping.
 */
import { PublicExportPublicKey, PublicExportSecretKey, PublicExportWrappingKey, PublicGenerateKeyPair, PublicGenerateWrappingKey, PublicGetPublicKey, PublicImportPublicKey, PublicImportSecretKey, PublicImportWrappingKey, PublicKeyID, SecretKeyID, PublicSign, PublicUnwrapSecretKey, PublicUnwrapSecretKeyWithPassword, PublicVerify, PublicWrapSecretKey, PublicWrapSecretKeyWithPassword, type CryptoKey, type Key } from 'paseto';
/**
 * Verification key used by the built-in v1.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v1.public';
    };
    readonly type: 'public';
    readonly version: 1;
    readonly kind: 'public';
}
/**
 * Wraps a native RSA-PSS public key for use with the built-in v1.public capabilities.
 *
 * The key must use SHA-384, a 2048-bit modulus, exponent 65537, and include the `verify` usage. The
 * exact public-key instance is retained, including when it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native RSA-PSS public key
 */
export declare function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey>;
/**
 * Returns the native RSA-PSS public key retained by a built-in v1.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v1.public key
 */
export declare function PublicKeyToCryptoKey(key: PublicKey): CryptoKey;
/**
 * Signing key used by the built-in v1.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v1.public';
    };
    readonly type: 'secret';
    readonly version: 1;
    readonly kind: 'secret';
}
/**
 * Wrapping key used by the built-in k1.secret-wrap.pie implementation.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
    readonly algorithm: {
        readonly name: 'PASERK k1.wrap';
    };
    readonly type: 'secret';
    readonly version: 1;
    readonly kind: 'wrapping';
}
/**
 * Wraps a native RSA-PSS private key for use with the built-in v1.public capabilities.
 *
 * The key must use SHA-384, a 2048-bit modulus, exponent 65537, and include the `sign` usage. The
 * exact private-key instance is retained. Its public key is obtained with
 * `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native RSA-PSS private key
 */
export declare function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey>;
/**
 * Returns the native RSA-PSS private key retained by a built-in v1.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v1.public secret key
 */
export declare function SecretKeyToCryptoKey(key: SecretKey): CryptoKey;
/**
 * Built-in v1.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export declare const GenerateKeyPairFactory: ReturnType<typeof PublicGenerateKeyPair<1, PublicKey, SecretKey>>;
/**
 * Built-in v1.public token-signing capability factory.
 *
 * @category Token Operations
 */
export declare const SignFactory: ReturnType<typeof PublicSign<1, SecretKey>>;
/**
 * Built-in v1.public token-verification capability factory.
 *
 * @category Token Operations
 */
export declare const VerifyFactory: ReturnType<typeof PublicVerify<1, PublicKey>>;
/**
 * Built-in PASERK k1.public key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<1, PublicKey>>;
/**
 * Built-in PASERK k1.public key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<1, PublicKey>>;
/**
 * Built-in PASERK k1.secret key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<1, SecretKey>>;
/**
 * Built-in PASERK k1.secret key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<1, SecretKey>>;
/**
 * Built-in PASERK k1 public-key derivation capability factory.
 *
 * @category Key Management
 */
export declare const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<1, PublicKey, SecretKey>>;
/**
 * Built-in PASERK k1.pid identifier capability factory.
 *
 * @category Key Management
 */
export declare const PublicKeyIDFactory: ReturnType<typeof PublicKeyID<1>>;
/**
 * Built-in PASERK k1.sid identifier capability factory.
 *
 * @category Key Management
 */
export declare const SecretKeyIDFactory: ReturnType<typeof SecretKeyID<1>>;
/**
 * Built-in PASERK k1 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export declare const GenerateWrappingKeyFactory: ReturnType<typeof PublicGenerateWrappingKey<1, WrappingKey>>;
/**
 * Built-in PASERK k1 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export declare const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<1, WrappingKey>>;
/**
 * Built-in PASERK k1 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export declare const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<1, WrappingKey>>;
/**
 * Built-in PASERK k1.secret-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const WrapSecretKeyFactory: ReturnType<typeof PublicWrapSecretKey<1, SecretKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k1.secret-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const UnwrapSecretKeyFactory: ReturnType<typeof PublicUnwrapSecretKey<1, SecretKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k1.secret-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const WrapSecretKeyWithPasswordFactory: ReturnType<typeof PublicWrapSecretKeyWithPassword<1, SecretKey>>;
/**
 * Built-in PASERK k1.secret-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const UnwrapSecretKeyWithPasswordFactory: ReturnType<typeof PublicUnwrapSecretKeyWithPassword<1, SecretKey>>;
//# sourceMappingURL=public.d.ts.map