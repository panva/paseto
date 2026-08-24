/**
 * Built-in PASETO and PASERK v4.local capability factories backed by standard runtime APIs.
 *
 * @module v4/local
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
 * Key used by the built-in v4.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v4.local' }
  readonly type: 'secret'
  readonly version: 4
  readonly kind: 'local'
}

/**
 * Wrapping key handled by the built-in k4 lifecycle capabilities.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
  readonly algorithm: { readonly name: 'PASERK k4.wrap' }
  readonly type: 'secret'
  readonly version: 4
  readonly kind: 'wrapping'
}

/**
 * Built-in v4.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<4, LocalKey>> =
  /* @__PURE__ */ LocalGenerateKey<4, LocalKey>({
    version: 4,
    run: (extractable) => generateLocalKeyModern(4, extractable),
  })

/**
 * Built-in PASERK k4.local key-import capability factory.
 *
 * @category Key Management
 */
export const ImportKeyFactory: ReturnType<typeof LocalImportKey<4, LocalKey>> =
  /* @__PURE__ */ LocalImportKey<4, LocalKey>({
    version: 4,
    run: (paserk, extractable) => importLocalKeyModern(4, paserk, extractable),
  })

/**
 * Built-in PASERK k4.local key-export capability factory.
 *
 * @category Key Management
 */
export const ExportKeyFactory: ReturnType<typeof LocalExportKey<4, LocalKey>> =
  /* @__PURE__ */ LocalExportKey<4, LocalKey>({ version: 4, run: (key) => exportLocalKey(4, key) })

/**
 * Built-in PASERK k4 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof LocalGenerateWrappingKey<4, WrappingKey>
> = /* @__PURE__ */ LocalGenerateWrappingKey<4, WrappingKey>({
  version: 4,
  run: (extractable) => generateWrappingKey(4, extractable),
})

/**
 * Built-in PASERK k4 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<4, WrappingKey>> =
  /* @__PURE__ */ LocalImportWrappingKey<4, WrappingKey>({
    version: 4,
    run: (material, extractable) => importWrappingKey(4, material, extractable),
  })

/**
 * Built-in PASERK k4 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<4, WrappingKey>> =
  /* @__PURE__ */ LocalExportWrappingKey<4, WrappingKey>({
    version: 4,
    run: (key) => exportWrappingKey(4, key),
  })
