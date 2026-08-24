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

import {
  LocalDecrypt,
  LocalEncrypt,
  LocalExportKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportWrappingKey,
  LocalKeyID,
  LocalUnwrapKey,
  LocalUnwrapKeyWithPassword,
  LocalWrapKey,
  LocalWrapKeyWithPassword,
  type CryptoKey,
  type Key,
} from '../index.ts'
import {
  decryptLocalV1,
  encryptLocalV1,
  exportLocalKey,
  exportWrappingKey,
  generateLocalKeyLegacy,
  generateWrappingKey,
  importLocalKeyLegacy,
  localKeyFromCryptoKey,
  localKeyToCryptoKey,
  importWrappingKey,
  localPaserkIdLegacy,
  unwrapLocalKeyLegacy,
  unwrapLocalKeyWithPasswordLegacy,
  wrapLocalKeyLegacy,
  wrapLocalKeyWithPasswordLegacy,
} from '../_internal/operations.ts'

/**
 * Key used by the built-in v1.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v1.local' }
  readonly type: 'secret'
  readonly version: 1
  readonly kind: 'local'
}

/**
 * Wrapping key used by the built-in k1.local-wrap.pie implementation.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
  readonly algorithm: { readonly name: 'PASERK k1.wrap' }
  readonly type: 'secret'
  readonly version: 1
  readonly kind: 'wrapping'
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
export function LocalKeyFromCryptoKey(key: CryptoKey): LocalKey {
  return localKeyFromCryptoKey(1, key)
}

/**
 * Returns the native HKDF key retained by a built-in v1.local key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v1.local key
 */
export function LocalKeyToCryptoKey(key: LocalKey): CryptoKey {
  return localKeyToCryptoKey(1, key)
}

/**
 * Built-in v1.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<1, LocalKey>> =
  /* @__PURE__ */ LocalGenerateKey<1, LocalKey>({
    version: 1,
    run: (extractable) => generateLocalKeyLegacy(1, extractable),
  })

/**
 * Built-in v1.local token-encryption capability factory.
 *
 * @category Token Operations
 */
export const EncryptFactory: ReturnType<typeof LocalEncrypt<1, LocalKey>> =
  /* @__PURE__ */ LocalEncrypt<1, LocalKey>({ version: 1, run: encryptLocalV1 })

/**
 * Built-in v1.local token-decryption capability factory.
 *
 * @category Token Operations
 */
export const DecryptFactory: ReturnType<typeof LocalDecrypt<1, LocalKey>> =
  /* @__PURE__ */ LocalDecrypt<1, LocalKey>({ version: 1, run: decryptLocalV1 })

/**
 * Built-in PASERK k1.local key-import capability factory.
 *
 * @category Key Management
 */
export const ImportKeyFactory: ReturnType<typeof LocalImportKey<1, LocalKey>> =
  /* @__PURE__ */ LocalImportKey<1, LocalKey>({
    version: 1,
    run: (paserk, extractable) => importLocalKeyLegacy(1, paserk, extractable),
  })

/**
 * Built-in PASERK k1.local key-export capability factory.
 *
 * @category Key Management
 */
export const ExportKeyFactory: ReturnType<typeof LocalExportKey<1, LocalKey>> =
  /* @__PURE__ */ LocalExportKey<1, LocalKey>({ version: 1, run: (key) => exportLocalKey(1, key) })

/**
 * Built-in PASERK k1.lid identifier capability factory.
 *
 * @category Key Management
 */
export const KeyIDFactory: ReturnType<typeof LocalKeyID<1>> = /* @__PURE__ */ LocalKeyID<1>({
  version: 1,
  run: (paserk) => localPaserkIdLegacy(1, paserk),
})

/**
 * Built-in PASERK k1 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof LocalGenerateWrappingKey<1, WrappingKey>
> = /* @__PURE__ */ LocalGenerateWrappingKey<1, WrappingKey>({
  version: 1,
  run: (extractable) => generateWrappingKey(1, extractable),
})

/**
 * Built-in PASERK k1 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<1, WrappingKey>> =
  /* @__PURE__ */ LocalImportWrappingKey<1, WrappingKey>({
    version: 1,
    run: (material, extractable) => importWrappingKey(1, material, extractable),
  })

/**
 * Built-in PASERK k1 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<1, WrappingKey>> =
  /* @__PURE__ */ LocalExportWrappingKey<1, WrappingKey>({
    version: 1,
    run: (key) => exportWrappingKey(1, key),
  })

/**
 * Built-in PASERK k1.local-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export const WrapKeyFactory: ReturnType<typeof LocalWrapKey<1, LocalKey, WrappingKey, 'pie'>> =
  /* @__PURE__ */ LocalWrapKey<1, LocalKey, WrappingKey, 'pie'>({
    version: 1,
    run: (key, wrappingKey) => wrapLocalKeyLegacy(1, key, wrappingKey),
  })

/**
 * Built-in PASERK k1.local-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export const UnwrapKeyFactory: ReturnType<typeof LocalUnwrapKey<1, LocalKey, WrappingKey, 'pie'>> =
  /* @__PURE__ */ LocalUnwrapKey<1, LocalKey, WrappingKey, 'pie'>({
    version: 1,
    run: (paserk, wrappingKey, extractable) =>
      unwrapLocalKeyLegacy(1, paserk, wrappingKey, extractable),
  })

/**
 * Built-in PASERK k1.local-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const WrapKeyWithPasswordFactory: ReturnType<typeof LocalWrapKeyWithPassword<1, LocalKey>> =
  /* @__PURE__ */ LocalWrapKeyWithPassword<1, LocalKey>({
    version: 1,
    run: (key, password, options) =>
      wrapLocalKeyWithPasswordLegacy(1, key, password, options ?? {}),
  })

/**
 * Built-in PASERK k1.local-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const UnwrapKeyWithPasswordFactory: ReturnType<
  typeof LocalUnwrapKeyWithPassword<1, LocalKey>
> = /* @__PURE__ */ LocalUnwrapKeyWithPassword<1, LocalKey>({
  version: 1,
  run: (paserk, password, limits, extractable) =>
    unwrapLocalKeyWithPasswordLegacy(1, paserk, password, limits, extractable),
})
