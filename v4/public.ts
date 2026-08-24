/**
 * Built-in PASETO and PASERK v4.public capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v4/public
 * @category Public Implementations
 * @categoryDescription Token Operations
 * Factories for signing and verifying v4.public tokens.
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
  generatePublicKeyPairV4,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV4,
  importSecretKeyV4,
  importWrappingKey,
  publicKeyFromCryptoKeyV4,
  publicKeyToCryptoKey,
  secretKeyFromCryptoKeyV4,
  secretKeyToCryptoKey,
  signPublicV4,
  verifyPublicV4,
} from '../_internal/operations.ts'

/**
 * Verification key used by the built-in v4.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v4.public' }
  readonly type: 'public'
  readonly version: 4
  readonly kind: 'public'
}

/**
 * Wraps a native Ed25519 public key for use with the built-in v4.public capabilities.
 *
 * The key usages must include `verify`. The exact public-key instance is retained, including when
 * it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native Ed25519 public key
 */
export async function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey> {
  return await publicKeyFromCryptoKeyV4(key)
}

/**
 * Returns the native Ed25519 public key retained by a built-in v4.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v4.public key
 */
export function PublicKeyToCryptoKey(key: PublicKey): CryptoKey {
  return publicKeyToCryptoKey(4, key)
}

/**
 * Signing key used by the built-in v4.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v4.public' }
  readonly type: 'secret'
  readonly version: 4
  readonly kind: 'secret'
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
 * Wraps a native Ed25519 private key for use with the built-in v4.public capabilities.
 *
 * The key usages must include `sign`. The exact private-key instance is retained. Its public key is
 * obtained with `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native Ed25519 private key
 */
export async function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey> {
  return await secretKeyFromCryptoKeyV4(key)
}

/**
 * Returns the native Ed25519 private key retained by a built-in v4.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v4.public secret key
 */
export function SecretKeyToCryptoKey(key: SecretKey): CryptoKey {
  return secretKeyToCryptoKey(4, key)
}

/**
 * Built-in v4.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyPairFactory: ReturnType<
  typeof PublicGenerateKeyPair<4, PublicKey, SecretKey>
> = /* @__PURE__ */ PublicGenerateKeyPair<4, PublicKey, SecretKey>({
  version: 4,
  run: generatePublicKeyPairV4,
})

/**
 * Built-in v4.public token-signing capability factory.
 *
 * @category Token Operations
 */
export const SignFactory: ReturnType<typeof PublicSign<4, SecretKey>> = /* @__PURE__ */ PublicSign<
  4,
  SecretKey
>({ version: 4, run: signPublicV4 })

/**
 * Built-in v4.public token-verification capability factory.
 *
 * @category Token Operations
 */
export const VerifyFactory: ReturnType<typeof PublicVerify<4, PublicKey>> =
  /* @__PURE__ */ PublicVerify<4, PublicKey>({ version: 4, run: verifyPublicV4 })

/**
 * Built-in PASERK k4.public key-import capability factory.
 *
 * @category Key Management
 */
export const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<4, PublicKey>> =
  /* @__PURE__ */ PublicImportPublicKey<4, PublicKey>({ version: 4, run: importPublicKeyV4 })

/**
 * Built-in PASERK k4.public key-export capability factory.
 *
 * @category Key Management
 */
export const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<4, PublicKey>> =
  /* @__PURE__ */ PublicExportPublicKey<4, PublicKey>({
    version: 4,
    run: (key) => exportPublicKey(4, key),
  })

/**
 * Built-in PASERK k4.secret key-import capability factory.
 *
 * @category Key Management
 */
export const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<4, SecretKey>> =
  /* @__PURE__ */ PublicImportSecretKey<4, SecretKey>({ version: 4, run: importSecretKeyV4 })

/**
 * Built-in PASERK k4.secret key-export capability factory.
 *
 * @category Key Management
 */
export const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<4, SecretKey>> =
  /* @__PURE__ */ PublicExportSecretKey<4, SecretKey>({
    version: 4,
    run: (key) => exportSecretKey(4, key),
  })

/**
 * Built-in PASERK k4 public-key derivation capability factory.
 *
 * @category Key Management
 */
export const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<4, PublicKey, SecretKey>> =
  /* @__PURE__ */ PublicGetPublicKey<4, PublicKey, SecretKey>({
    version: 4,
    run: (key) => getPublicKey(4, key),
  })

/**
 * Built-in PASERK k4 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof PublicGenerateWrappingKey<4, WrappingKey>
> = /* @__PURE__ */ PublicGenerateWrappingKey<4, WrappingKey>({
  version: 4,
  run: (extractable) => generateWrappingKey(4, extractable),
})

/**
 * Built-in PASERK k4 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<4, WrappingKey>> =
  /* @__PURE__ */ PublicImportWrappingKey<4, WrappingKey>({
    version: 4,
    run: (material, extractable) => importWrappingKey(4, material, extractable),
  })

/**
 * Built-in PASERK k4 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<4, WrappingKey>> =
  /* @__PURE__ */ PublicExportWrappingKey<4, WrappingKey>({
    version: 4,
    run: (key) => exportWrappingKey(4, key),
  })
