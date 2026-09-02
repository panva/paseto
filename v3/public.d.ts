/**
 * Built-in PASETO and PASERK v3.public capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v3/public
 * @category Public Implementations
 * @categoryDescription Token Operations
 * Factories for signing and verifying v3.public tokens.
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
 * Verification key used by the built-in v3.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v3.public';
    };
    readonly type: 'public';
    readonly version: 3;
    readonly kind: 'public';
}
/**
 * Wraps a native ECDSA P-384 public key for use with the built-in v3.public capabilities.
 *
 * The key usages must include `verify` and the key must be extractable. v3.public includes the
 * encoded public key in its pre-authentication encoding, so a native handle alone is insufficient.
 * The exact public-key instance is retained.
 *
 * @category CryptoKey Adapters
 * @param key - Native ECDSA P-384 public key
 */
export declare function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey>;
/**
 * Returns the native ECDSA P-384 public key retained by a built-in v3.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v3.public key
 */
export declare function PublicKeyToCryptoKey(key: PublicKey): CryptoKey;
/**
 * Signing key used by the built-in v3.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v3.public';
    };
    readonly type: 'secret';
    readonly version: 3;
    readonly kind: 'secret';
}
/**
 * Wrapping key used by the built-in k3.secret-wrap.pie implementation.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
    readonly algorithm: {
        readonly name: 'PASERK k3.wrap';
    };
    readonly type: 'secret';
    readonly version: 3;
    readonly kind: 'wrapping';
}
/**
 * Wraps a native ECDSA P-384 private key for use with the built-in v3.public capabilities.
 *
 * The key usages must include `sign`. The exact private-key instance is retained. Its public key is
 * obtained with `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native ECDSA P-384 private key
 */
export declare function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey>;
/**
 * Returns the native ECDSA private key retained by a built-in v3.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v3.public secret key
 */
export declare function SecretKeyToCryptoKey(key: SecretKey): CryptoKey;
/**
 * Built-in v3.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export declare const GenerateKeyPairFactory: ReturnType<typeof PublicGenerateKeyPair<3, PublicKey, SecretKey>>;
/**
 * Built-in v3.public token-signing capability factory.
 *
 * @category Token Operations
 */
export declare const SignFactory: ReturnType<typeof PublicSign<3, SecretKey>>;
/**
 * Built-in v3.public token-verification capability factory.
 *
 * @category Token Operations
 */
export declare const VerifyFactory: ReturnType<typeof PublicVerify<3, PublicKey>>;
/**
 * Built-in PASERK k3.public key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<3, PublicKey>>;
/**
 * Built-in PASERK k3.public key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<3, PublicKey>>;
/**
 * Built-in PASERK k3.secret key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<3, SecretKey>>;
/**
 * Built-in PASERK k3.secret key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<3, SecretKey>>;
/**
 * Built-in PASERK k3 public-key derivation capability factory.
 *
 * @category Key Management
 */
export declare const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<3, PublicKey, SecretKey>>;
/**
 * Built-in PASERK k3.pid identifier capability factory.
 *
 * @category Key Management
 */
export declare const PublicKeyIDFactory: ReturnType<typeof PublicKeyID<3>>;
/**
 * Built-in PASERK k3.sid identifier capability factory.
 *
 * @category Key Management
 */
export declare const SecretKeyIDFactory: ReturnType<typeof SecretKeyID<3>>;
/**
 * Built-in PASERK k3 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export declare const GenerateWrappingKeyFactory: ReturnType<typeof PublicGenerateWrappingKey<3, WrappingKey>>;
/**
 * Built-in PASERK k3 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export declare const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<3, WrappingKey>>;
/**
 * Built-in PASERK k3 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export declare const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<3, WrappingKey>>;
/**
 * Built-in PASERK k3.secret-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const WrapSecretKeyFactory: ReturnType<typeof PublicWrapSecretKey<3, SecretKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k3.secret-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const UnwrapSecretKeyFactory: ReturnType<typeof PublicUnwrapSecretKey<3, SecretKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k3.secret-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const WrapSecretKeyWithPasswordFactory: ReturnType<typeof PublicWrapSecretKeyWithPassword<3, SecretKey>>;
/**
 * Built-in PASERK k3.secret-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const UnwrapSecretKeyWithPasswordFactory: ReturnType<typeof PublicUnwrapSecretKeyWithPassword<3, SecretKey>>;
//# sourceMappingURL=public.d.ts.map