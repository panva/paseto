/**
 * Built-in PASETO and PASERK v2.local capability factories backed by standard runtime APIs.
 *
 * @module v2/local
 * @category Local Implementations
 * @categoryDescription Key Management
 * The local key type and factories for generating, importing, and exporting local keys.
 *
 * @categoryDescription Key Wrapping
 * The wrapping key type and its generation, import, and export factories.
 */
import { LocalExportKey, LocalExportWrappingKey, LocalGenerateKey, LocalGenerateWrappingKey, LocalImportKey, LocalImportWrappingKey, type Key } from 'paseto';
/**
 * Key used by the built-in v2.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
    readonly algorithm: {
        readonly name: 'PASETO v2.local';
    };
    readonly type: 'secret';
    readonly version: 2;
    readonly kind: 'local';
}
/**
 * Wrapping key handled by the built-in k2 lifecycle capabilities.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
    readonly algorithm: {
        readonly name: 'PASERK k2.wrap';
    };
    readonly type: 'secret';
    readonly version: 2;
    readonly kind: 'wrapping';
}
/**
 * Built-in v2.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export declare const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<2, LocalKey>>;
/**
 * Built-in PASERK k2.local key-import capability factory.
 *
 * @category Key Management
 */
export declare const ImportKeyFactory: ReturnType<typeof LocalImportKey<2, LocalKey>>;
/**
 * Built-in PASERK k2.local key-export capability factory.
 *
 * @category Key Management
 */
export declare const ExportKeyFactory: ReturnType<typeof LocalExportKey<2, LocalKey>>;
/**
 * Built-in PASERK k2 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export declare const GenerateWrappingKeyFactory: ReturnType<typeof LocalGenerateWrappingKey<2, WrappingKey>>;
/**
 * Built-in PASERK k2 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export declare const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<2, WrappingKey>>;
/**
 * Built-in PASERK k2 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export declare const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<2, WrappingKey>>;
//# sourceMappingURL=local.d.ts.map