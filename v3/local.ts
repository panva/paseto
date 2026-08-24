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

import {
  LocalDecrypt,
  LocalEncrypt,
  LocalExportKey,
  LocalExportSealingPublicKey,
  LocalExportSealingSecretKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateSealingKeyPair,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportSealingPublicKey,
  LocalImportSealingSecretKey,
  LocalImportWrappingKey,
  LocalKeyID,
  LocalSealKey,
  LocalUnsealKey,
  LocalUnwrapKey,
  LocalUnwrapKeyWithPassword,
  LocalWrapKey,
  LocalWrapKeyWithPassword,
  type CryptoKey,
  type Key,
} from '../index.ts'
import {
  decryptLocalV3,
  encryptLocalV3,
  exportLocalKey,
  exportSealingPublicKeyV3,
  exportSealingSecretKeyV3,
  exportWrappingKey,
  generateLocalKeyLegacy,
  generateSealingKeyPairV3,
  generateWrappingKey,
  importLocalKeyLegacy,
  localKeyFromCryptoKey,
  localKeyToCryptoKey,
  importSealingPublicKeyV3,
  importSealingSecretKeyV3,
  importWrappingKey,
  localPaserkIdLegacy,
  sealLocalKeyV3,
  unsealLocalKeyV3,
  unwrapLocalKeyLegacy,
  unwrapLocalKeyWithPasswordLegacy,
  wrapLocalKeyLegacy,
  wrapLocalKeyWithPasswordLegacy,
} from '../_internal/operations.ts'

/**
 * Key used by the built-in v3.local implementations.
 *
 * @category Key Management
 */
export interface LocalKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v3.local' }
  readonly type: 'secret'
  readonly version: 3
  readonly kind: 'local'
}

/**
 * Wrapping key used by the built-in k3.local-wrap.pie implementation.
 *
 * @category Key Wrapping
 */
export interface WrappingKey extends Key {
  readonly algorithm: { readonly name: 'PASERK k3.wrap' }
  readonly type: 'secret'
  readonly version: 3
  readonly kind: 'wrapping'
}

/**
 * Public recipient key used by the built-in k3.seal implementation.
 *
 * @category Key Sealing
 */
export interface SealingPublicKey extends Key {
  readonly algorithm: { readonly name: 'PASERK k3.seal' }
  readonly extractable: true
  readonly type: 'public'
  readonly version: 3
  readonly kind: 'sealing-public'
}

/**
 * Secret recipient key used by the built-in k3.seal implementation.
 *
 * @category Key Sealing
 */
export interface SealingSecretKey extends Key {
  readonly algorithm: { readonly name: 'PASERK k3.seal' }
  readonly type: 'secret'
  readonly version: 3
  readonly kind: 'sealing-secret'
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
export function LocalKeyFromCryptoKey(key: CryptoKey): LocalKey {
  return localKeyFromCryptoKey(3, key)
}

/**
 * Returns the native HKDF key retained by a built-in v3.local key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v3.local key
 */
export function LocalKeyToCryptoKey(key: LocalKey): CryptoKey {
  return localKeyToCryptoKey(3, key)
}

/**
 * Built-in v3.local symmetric-key generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyFactory: ReturnType<typeof LocalGenerateKey<3, LocalKey>> =
  /* @__PURE__ */ LocalGenerateKey<3, LocalKey>({
    version: 3,
    run: (extractable) => generateLocalKeyLegacy(3, extractable),
  })

/**
 * Built-in v3.local token-encryption capability factory.
 *
 * @category Token Operations
 */
export const EncryptFactory: ReturnType<typeof LocalEncrypt<3, LocalKey>> =
  /* @__PURE__ */ LocalEncrypt<3, LocalKey>({ version: 3, run: encryptLocalV3 })

/**
 * Built-in v3.local token-decryption capability factory.
 *
 * @category Token Operations
 */
export const DecryptFactory: ReturnType<typeof LocalDecrypt<3, LocalKey>> =
  /* @__PURE__ */ LocalDecrypt<3, LocalKey>({ version: 3, run: decryptLocalV3 })

/**
 * Built-in PASERK k3.local key-import capability factory.
 *
 * @category Key Management
 */
export const ImportKeyFactory: ReturnType<typeof LocalImportKey<3, LocalKey>> =
  /* @__PURE__ */ LocalImportKey<3, LocalKey>({
    version: 3,
    run: (paserk, extractable) => importLocalKeyLegacy(3, paserk, extractable),
  })

/**
 * Built-in PASERK k3.local key-export capability factory.
 *
 * @category Key Management
 */
export const ExportKeyFactory: ReturnType<typeof LocalExportKey<3, LocalKey>> =
  /* @__PURE__ */ LocalExportKey<3, LocalKey>({ version: 3, run: (key) => exportLocalKey(3, key) })

/**
 * Built-in PASERK k3.lid identifier capability factory.
 *
 * @category Key Management
 */
export const KeyIDFactory: ReturnType<typeof LocalKeyID<3>> = /* @__PURE__ */ LocalKeyID<3>({
  version: 3,
  run: (paserk) => localPaserkIdLegacy(3, paserk),
})

/**
 * Built-in PASERK k3 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof LocalGenerateWrappingKey<3, WrappingKey>
> = /* @__PURE__ */ LocalGenerateWrappingKey<3, WrappingKey>({
  version: 3,
  run: (extractable) => generateWrappingKey(3, extractable),
})

/**
 * Built-in PASERK k3 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof LocalImportWrappingKey<3, WrappingKey>> =
  /* @__PURE__ */ LocalImportWrappingKey<3, WrappingKey>({
    version: 3,
    run: (material, extractable) => importWrappingKey(3, material, extractable),
  })

/**
 * Built-in PASERK k3 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof LocalExportWrappingKey<3, WrappingKey>> =
  /* @__PURE__ */ LocalExportWrappingKey<3, WrappingKey>({
    version: 3,
    run: (key) => exportWrappingKey(3, key),
  })

/**
 * Built-in PASERK k3.local-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export const WrapKeyFactory: ReturnType<typeof LocalWrapKey<3, LocalKey, WrappingKey, 'pie'>> =
  /* @__PURE__ */ LocalWrapKey<3, LocalKey, WrappingKey, 'pie'>({
    version: 3,
    run: (key, wrappingKey) => wrapLocalKeyLegacy(3, key, wrappingKey),
  })

/**
 * Built-in PASERK k3.local-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export const UnwrapKeyFactory: ReturnType<typeof LocalUnwrapKey<3, LocalKey, WrappingKey, 'pie'>> =
  /* @__PURE__ */ LocalUnwrapKey<3, LocalKey, WrappingKey, 'pie'>({
    version: 3,
    run: (paserk, wrappingKey, extractable) =>
      unwrapLocalKeyLegacy(3, paserk, wrappingKey, extractable),
  })

/**
 * Built-in PASERK k3.local-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const WrapKeyWithPasswordFactory: ReturnType<typeof LocalWrapKeyWithPassword<3, LocalKey>> =
  /* @__PURE__ */ LocalWrapKeyWithPassword<3, LocalKey>({
    version: 3,
    run: (key, password, options) =>
      wrapLocalKeyWithPasswordLegacy(3, key, password, options ?? {}),
  })

/**
 * Built-in PASERK k3.local-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const UnwrapKeyWithPasswordFactory: ReturnType<
  typeof LocalUnwrapKeyWithPassword<3, LocalKey>
> = /* @__PURE__ */ LocalUnwrapKeyWithPassword<3, LocalKey>({
  version: 3,
  run: (paserk, password, limits, extractable) =>
    unwrapLocalKeyWithPasswordLegacy(3, paserk, password, limits, extractable),
})

/**
 * Built-in PASERK k3.seal recipient key-pair generation capability factory.
 *
 * @category Key Sealing
 */
export const GenerateSealingKeyPairFactory: ReturnType<
  typeof LocalGenerateSealingKeyPair<3, SealingPublicKey, SealingSecretKey>
> = /* @__PURE__ */ LocalGenerateSealingKeyPair<3, SealingPublicKey, SealingSecretKey>({
  version: 3,
  run: generateSealingKeyPairV3,
})

/**
 * Built-in PASERK k3.seal public-key import capability factory.
 *
 * @category Key Sealing
 */
export const ImportSealingPublicKeyFactory: ReturnType<
  typeof LocalImportSealingPublicKey<3, SealingPublicKey>
> = /* @__PURE__ */ LocalImportSealingPublicKey<3, SealingPublicKey>({
  version: 3,
  run: importSealingPublicKeyV3,
})

/**
 * Built-in PASERK k3.seal secret-key import capability factory.
 *
 * @category Key Sealing
 */
export const ImportSealingSecretKeyFactory: ReturnType<
  typeof LocalImportSealingSecretKey<3, SealingSecretKey>
> = /* @__PURE__ */ LocalImportSealingSecretKey<3, SealingSecretKey>({
  version: 3,
  run: importSealingSecretKeyV3,
})

/**
 * Built-in PASERK k3.seal public-key export capability factory.
 *
 * @category Key Sealing
 */
export const ExportSealingPublicKeyFactory: ReturnType<
  typeof LocalExportSealingPublicKey<3, SealingPublicKey>
> = /* @__PURE__ */ LocalExportSealingPublicKey<3, SealingPublicKey>({
  version: 3,
  run: exportSealingPublicKeyV3,
})

/**
 * Built-in PASERK k3.seal secret-key export capability factory.
 *
 * @category Key Sealing
 */
export const ExportSealingSecretKeyFactory: ReturnType<
  typeof LocalExportSealingSecretKey<3, SealingSecretKey>
> = /* @__PURE__ */ LocalExportSealingSecretKey<3, SealingSecretKey>({
  version: 3,
  run: exportSealingSecretKeyV3,
})

/**
 * Built-in PASERK k3.seal key-sealing capability factory.
 *
 * @category Key Sealing
 */
export const SealKeyFactory: ReturnType<typeof LocalSealKey<3, LocalKey, SealingPublicKey>> =
  /* @__PURE__ */ LocalSealKey<3, LocalKey, SealingPublicKey>({ version: 3, run: sealLocalKeyV3 })

/**
 * Built-in PASERK k3.seal key-unsealing capability factory.
 *
 * @category Key Sealing
 */
export const UnsealKeyFactory: ReturnType<typeof LocalUnsealKey<3, LocalKey, SealingSecretKey>> =
  /* @__PURE__ */ LocalUnsealKey<3, LocalKey, SealingSecretKey>({
    version: 3,
    run: unsealLocalKeyV3,
  })
