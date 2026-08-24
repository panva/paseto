/**
 * Built-in PASETO and PASERK v2.public capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v2/public
 * @category Public Implementations
 * @categoryDescription Token Operations
 * Factories for signing and verifying v2.public tokens.
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

import {
  PublicExportPublicKey,
  PublicExportSecretKey,
  PublicExportWrappingKey,
  PublicGenerateKeyPair,
  PublicGenerateWrappingKey,
  PublicGetPublicKey,
  PublicImportPublicKey,
  PublicImportSecretKey,
  PublicImportWrappingKey,
  PublicSign,
  PublicVerify,
  type CryptoKey,
  type Key,
} from '../index.ts'
import {
  exportPublicKey,
  exportSecretKey,
  exportWrappingKey,
  generatePublicKeyPairV2,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV2,
  importSecretKeyV2,
  importWrappingKey,
  publicKeyFromCryptoKeyV2,
  publicKeyToCryptoKey,
  secretKeyFromCryptoKeyV2,
  secretKeyToCryptoKey,
  signPublicV2,
  verifyPublicV2,
} from '../_internal/operations.ts'

/**
 * Verification key used by the built-in v2.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v2.public' }
  readonly type: 'public'
  readonly version: 2
  readonly kind: 'public'
}

/**
 * Wraps a native Ed25519 public key for use with the built-in v2.public capabilities.
 *
 * The key usages must include `verify`. The exact public-key instance is retained, including when
 * it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native Ed25519 public key
 */
export async function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey> {
  return await publicKeyFromCryptoKeyV2(key)
}

/**
 * Returns the native Ed25519 public key retained by a built-in v2.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v2.public key
 */
export function PublicKeyToCryptoKey(key: PublicKey): CryptoKey {
  return publicKeyToCryptoKey(2, key)
}

/**
 * Signing key used by the built-in v2.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v2.public' }
  readonly type: 'secret'
  readonly version: 2
  readonly kind: 'secret'
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
 * Wraps a native Ed25519 private key for use with the built-in v2.public capabilities.
 *
 * The key usages must include `sign`. The exact private-key instance is retained. Its public key is
 * obtained with `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native Ed25519 private key
 */
export async function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey> {
  return await secretKeyFromCryptoKeyV2(key)
}

/**
 * Returns the native Ed25519 private key retained by a built-in v2.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v2.public secret key
 */
export function SecretKeyToCryptoKey(key: SecretKey): CryptoKey {
  return secretKeyToCryptoKey(2, key)
}

/**
 * Built-in v2.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyPairFactory: ReturnType<
  typeof PublicGenerateKeyPair<2, PublicKey, SecretKey>
> = /* @__PURE__ */ PublicGenerateKeyPair<2, PublicKey, SecretKey>({
  version: 2,
  run: generatePublicKeyPairV2,
})

/**
 * Built-in v2.public token-signing capability factory.
 *
 * @category Token Operations
 */
export const SignFactory: ReturnType<typeof PublicSign<2, SecretKey>> = /* @__PURE__ */ PublicSign<
  2,
  SecretKey
>({ version: 2, run: signPublicV2 })

/**
 * Built-in v2.public token-verification capability factory.
 *
 * @category Token Operations
 */
export const VerifyFactory: ReturnType<typeof PublicVerify<2, PublicKey>> =
  /* @__PURE__ */ PublicVerify<2, PublicKey>({ version: 2, run: verifyPublicV2 })

/**
 * Built-in PASERK k2.public key-import capability factory.
 *
 * @category Key Management
 */
export const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<2, PublicKey>> =
  /* @__PURE__ */ PublicImportPublicKey<2, PublicKey>({ version: 2, run: importPublicKeyV2 })

/**
 * Built-in PASERK k2.public key-export capability factory.
 *
 * @category Key Management
 */
export const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<2, PublicKey>> =
  /* @__PURE__ */ PublicExportPublicKey<2, PublicKey>({
    version: 2,
    run: (key) => exportPublicKey(2, key),
  })

/**
 * Built-in PASERK k2.secret key-import capability factory.
 *
 * @category Key Management
 */
export const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<2, SecretKey>> =
  /* @__PURE__ */ PublicImportSecretKey<2, SecretKey>({ version: 2, run: importSecretKeyV2 })

/**
 * Built-in PASERK k2.secret key-export capability factory.
 *
 * @category Key Management
 */
export const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<2, SecretKey>> =
  /* @__PURE__ */ PublicExportSecretKey<2, SecretKey>({
    version: 2,
    run: (key) => exportSecretKey(2, key),
  })

/**
 * Built-in PASERK k2 public-key derivation capability factory.
 *
 * @category Key Management
 */
export const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<2, PublicKey, SecretKey>> =
  /* @__PURE__ */ PublicGetPublicKey<2, PublicKey, SecretKey>({
    version: 2,
    run: (key) => getPublicKey(2, key),
  })

/**
 * Built-in PASERK k2 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof PublicGenerateWrappingKey<2, WrappingKey>
> = /* @__PURE__ */ PublicGenerateWrappingKey<2, WrappingKey>({
  version: 2,
  run: (extractable) => generateWrappingKey(2, extractable),
})

/**
 * Built-in PASERK k2 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<2, WrappingKey>> =
  /* @__PURE__ */ PublicImportWrappingKey<2, WrappingKey>({
    version: 2,
    run: (material, extractable) => importWrappingKey(2, material, extractable),
  })

/**
 * Built-in PASERK k2 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<2, WrappingKey>> =
  /* @__PURE__ */ PublicExportWrappingKey<2, WrappingKey>({
    version: 2,
    run: (key) => exportWrappingKey(2, key),
  })
