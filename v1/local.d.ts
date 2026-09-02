/**
 * Built-in PASETO and PASERK v1.local capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v1/local
 * @category Local Implementations
 * @categoryDescription Token Operations
 * Factories for encrypting and decrypting v1.local tokens.
 *
 * @categoryDescription Key Management
 * The local key type and factories for generating, importing, exporting, and identifying local
 * keys.
 *
 * @categoryDescription CryptoKey Adapters
 * Adapters between native HKDF `CryptoKey` instances and built-in local keys.
 *
 * @categoryDescription Key Wrapping
 * The wrapping key type and factories for managing wrapping keys and wrapping local keys with PIE.
 *
 * @categoryDescription Password-Based Key Wrapping
 * Factories for password-based local-key wrapping and unwrapping.
 */
import { LocalDecrypt, LocalEncrypt, LocalExportKey, LocalExportWrappingKey, LocalGenerateKey, LocalGenerateWrappingKey, LocalImportKey, LocalImportWrappingKey, LocalKeyID, LocalUnwrapKey, LocalUnwrapKeyWithPassword, LocalWrapKey, LocalWrapKeyWithPassword, type CryptoKey, type Key } from 'paseto';
/**
 * Key used by the built-in v1.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v1.local';
    };
    readonly type: 'secret';
    readonly version: 1;
    readonly kind: 'local';
}
/**
 * Wrapping key used by the built-in k1.local-wrap.pie implementation.
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
 * Wraps a native HKDF key for use with the built-in v1.local capabilities.
 *
 * The key must be a secret `CryptoKey` whose usages include `deriveBits`. The exact key instance is
 * retained, including when it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native HKDF key
 */
export declare function LocalKeyFromCryptoKey(key: CryptoKey): LocalKey;
/**
 * Returns the native HKDF key retained by a built-in v1.local key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v1.local key
 */
export declare function LocalKeyToCryptoKey(key: LocalKey): CryptoKey;
/**
 * Built-in v1.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export declare const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<1, LocalKey>>;
/**
 * Built-in v1.local token-encryption capability factory.
 *
 * @category Token Operations
 */
export declare const EncryptFactory: ReturnType<typeof LocalEncrypt<1, LocalKey>>;
/**
 * Built-in v1.local token-decryption capability factory.
 *
 * @category Token Operations
 */
export declare const DecryptFactory: ReturnType<typeof LocalDecrypt<1, LocalKey>>;
/**
 * Built-in PASERK k1.local key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportKeyFactory: ReturnType<typeof LocalImportKey<1, LocalKey>>;
/**
 * Built-in PASERK k1.local key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportKeyFactory: ReturnType<typeof LocalExportKey<1, LocalKey>>;
/**
 * Built-in PASERK k1.lid identifier capability factory.
 *
 * @category Key Management
 */
export declare const KeyIDFactory: ReturnType<typeof LocalKeyID<1>>;
/**
 * Built-in PASERK k1 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export declare const GenerateWrappingKeyFactory: ReturnType<typeof LocalGenerateWrappingKey<1, WrappingKey>>;
/**
 * Built-in PASERK k1 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export declare const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<1, WrappingKey>>;
/**
 * Built-in PASERK k1 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export declare const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<1, WrappingKey>>;
/**
 * Built-in PASERK k1.local-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const WrapKeyFactory: ReturnType<typeof LocalWrapKey<1, LocalKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k1.local-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const UnwrapKeyFactory: ReturnType<typeof LocalUnwrapKey<1, LocalKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k1.local-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const WrapKeyWithPasswordFactory: ReturnType<typeof LocalWrapKeyWithPassword<1, LocalKey>>;
/**
 * Built-in PASERK k1.local-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const UnwrapKeyWithPasswordFactory: ReturnType<typeof LocalUnwrapKeyWithPassword<1, LocalKey>>;
//# sourceMappingURL=local.d.ts.map