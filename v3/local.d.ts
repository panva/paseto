/**
 * Built-in PASETO and PASERK v3.local capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v3/local
 * @category Local Implementations
 * @categoryDescription Token Operations
 * Factories for encrypting and decrypting v3.local tokens.
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
 *
 * @categoryDescription Key Sealing
 * Sealing key types and factories for managing recipient keys and sealing local keys.
 */
import { LocalDecrypt, LocalEncrypt, LocalExportKey, LocalExportSealingPublicKey, LocalExportSealingSecretKey, LocalExportWrappingKey, LocalGenerateKey, LocalGenerateSealingKeyPair, LocalGenerateWrappingKey, LocalImportKey, LocalImportSealingPublicKey, LocalImportSealingSecretKey, LocalImportWrappingKey, LocalKeyID, LocalSealKey, LocalUnsealKey, LocalUnwrapKey, LocalUnwrapKeyWithPassword, LocalWrapKey, LocalWrapKeyWithPassword, type CryptoKey, type Key } from 'paseto';
/**
 * Key used by the built-in v3.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v3.local';
    };
    readonly type: 'secret';
    readonly version: 3;
    readonly kind: 'local';
}
/**
 * Wrapping key used by the built-in k3.local-wrap.pie implementation.
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
 * Public recipient key used by the built-in k3.seal implementation.
 *
 * @category Key Sealing
 */
export interface SealingPublicKey extends Key {
    readonly algorithm: {
        readonly name: 'PASERK k3.seal';
    };
    readonly extractable: true;
    readonly type: 'public';
    readonly version: 3;
    readonly kind: 'sealing-public';
}
/**
 * Secret recipient key used by the built-in k3.seal implementation.
 *
 * @category Key Sealing
 */
export interface SealingSecretKey extends Key {
    readonly algorithm: {
        readonly name: 'PASERK k3.seal';
    };
    readonly type: 'secret';
    readonly version: 3;
    readonly kind: 'sealing-secret';
}
/**
 * Wraps a native HKDF key for use with the built-in v3.local capabilities.
 *
 * The key must be a secret `CryptoKey` whose usages include `deriveBits`. The exact key instance is
 * retained, including when it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native HKDF key
 */
export declare function LocalKeyFromCryptoKey(key: CryptoKey): LocalKey;
/**
 * Returns the native HKDF key retained by a built-in v3.local key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v3.local key
 */
export declare function LocalKeyToCryptoKey(key: LocalKey): CryptoKey;
/**
 * Built-in v3.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export declare const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<3, LocalKey>>;
/**
 * Built-in v3.local token-encryption capability factory.
 *
 * @category Token Operations
 */
export declare const EncryptFactory: ReturnType<typeof LocalEncrypt<3, LocalKey>>;
/**
 * Built-in v3.local token-decryption capability factory.
 *
 * @category Token Operations
 */
export declare const DecryptFactory: ReturnType<typeof LocalDecrypt<3, LocalKey>>;
/**
 * Built-in PASERK k3.local key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportKeyFactory: ReturnType<typeof LocalImportKey<3, LocalKey>>;
/**
 * Built-in PASERK k3.local key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportKeyFactory: ReturnType<typeof LocalExportKey<3, LocalKey>>;
/**
 * Built-in PASERK k3.lid identifier capability factory.
 *
 * @category Key Management
 */
export declare const KeyIDFactory: ReturnType<typeof LocalKeyID<3>>;
/**
 * Built-in PASERK k3 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export declare const GenerateWrappingKeyFactory: ReturnType<typeof LocalGenerateWrappingKey<3, WrappingKey>>;
/**
 * Built-in PASERK k3 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export declare const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<3, WrappingKey>>;
/**
 * Built-in PASERK k3 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export declare const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<3, WrappingKey>>;
/**
 * Built-in PASERK k3.local-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const WrapKeyFactory: ReturnType<typeof LocalWrapKey<3, LocalKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k3.local-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export declare const UnwrapKeyFactory: ReturnType<typeof LocalUnwrapKey<3, LocalKey, WrappingKey, 'pie'>>;
/**
 * Built-in PASERK k3.local-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const WrapKeyWithPasswordFactory: ReturnType<typeof LocalWrapKeyWithPassword<3, LocalKey>>;
/**
 * Built-in PASERK k3.local-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export declare const UnwrapKeyWithPasswordFactory: ReturnType<typeof LocalUnwrapKeyWithPassword<3, LocalKey>>;
/**
 * Built-in PASERK k3.seal recipient key-pair generation capability factory.
 *
 * @category Key Sealing
 */
export declare const GenerateSealingKeyPairFactory: ReturnType<typeof LocalGenerateSealingKeyPair<3, SealingPublicKey, SealingSecretKey>>;
/**
 * Built-in PASERK k3.seal public-key import capability factory.
 *
 * @category Key Sealing
 */
export declare const ImportSealingPublicKeyFactory: ReturnType<typeof LocalImportSealingPublicKey<3, SealingPublicKey>>;
/**
 * Built-in PASERK k3.seal secret-key import capability factory.
 *
 * @category Key Sealing
 */
export declare const ImportSealingSecretKeyFactory: ReturnType<typeof LocalImportSealingSecretKey<3, SealingSecretKey>>;
/**
 * Built-in PASERK k3.seal public-key export capability factory.
 *
 * @category Key Sealing
 */
export declare const ExportSealingPublicKeyFactory: ReturnType<typeof LocalExportSealingPublicKey<3, SealingPublicKey>>;
/**
 * Built-in PASERK k3.seal secret-key export capability factory.
 *
 * @category Key Sealing
 */
export declare const ExportSealingSecretKeyFactory: ReturnType<typeof LocalExportSealingSecretKey<3, SealingSecretKey>>;
/**
 * Built-in PASERK k3.seal key-sealing capability factory.
 *
 * @category Key Sealing
 */
export declare const SealKeyFactory: ReturnType<typeof LocalSealKey<3, LocalKey, SealingPublicKey>>;
/**
 * Built-in PASERK k3.seal key-unsealing capability factory.
 *
 * @category Key Sealing
 */
export declare const UnsealKeyFactory: ReturnType<typeof LocalUnsealKey<3, LocalKey, SealingSecretKey>>;
//# sourceMappingURL=local.d.ts.map