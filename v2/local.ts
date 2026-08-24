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

import {
  LocalExportKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportWrappingKey,
  type Key,
} from '../index.ts'
import {
  exportLocalKey,
  exportWrappingKey,
  generateLocalKeyModern,
  generateWrappingKey,
  importLocalKeyModern,
  importWrappingKey,
} from '../_internal/operations.ts'

/**
 * Key used by the built-in v2.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v2.local' }
  readonly type: 'secret'
  readonly version: 2
  readonly kind: 'local'
}

/**
 * Wrapping key handled by the built-in k2 lifecycle capabilities.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
  readonly algorithm: { readonly name: 'PASERK k2.wrap' }
  readonly type: 'secret'
  readonly version: 2
  readonly kind: 'wrapping'
}

/**
 * Built-in v2.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<2, LocalKey>> =
  /* @__PURE__ */ LocalGenerateKey<2, LocalKey>({
    version: 2,
    run: (extractable) => generateLocalKeyModern(2, extractable),
  })

/**
 * Built-in PASERK k2.local key-import capability factory.
 *
 * @category Key Management
 */
export const ImportKeyFactory: ReturnType<typeof LocalImportKey<2, LocalKey>> =
  /* @__PURE__ */ LocalImportKey<2, LocalKey>({
    version: 2,
    run: (paserk, extractable) => importLocalKeyModern(2, paserk, extractable),
  })

/**
 * Built-in PASERK k2.local key-export capability factory.
 *
 * @category Key Management
 */
export const ExportKeyFactory: ReturnType<typeof LocalExportKey<2, LocalKey>> =
  /* @__PURE__ */ LocalExportKey<2, LocalKey>({ version: 2, run: (key) => exportLocalKey(2, key) })

/**
 * Built-in PASERK k2 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof LocalGenerateWrappingKey<2, WrappingKey>
> = /* @__PURE__ */ LocalGenerateWrappingKey<2, WrappingKey>({
  version: 2,
  run: (extractable) => generateWrappingKey(2, extractable),
})

/**
 * Built-in PASERK k2 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<2, WrappingKey>> =
  /* @__PURE__ */ LocalImportWrappingKey<2, WrappingKey>({
    version: 2,
    run: (material, extractable) => importWrappingKey(2, material, extractable),
  })

/**
 * Built-in PASERK k2 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<2, WrappingKey>> =
  /* @__PURE__ */ LocalExportWrappingKey<2, WrappingKey>({
    version: 2,
    run: (key) => exportWrappingKey(2, key),
  })
