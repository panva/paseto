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
  PublicKeyID,
  SecretKeyID,
  PublicSign,
  PublicUnwrapSecretKey,
  PublicUnwrapSecretKeyWithPassword,
  PublicVerify,
  PublicWrapSecretKey,
  PublicWrapSecretKeyWithPassword,
  type CryptoKey,
  type Key,
} from '../index.ts'
import {
  exportPublicKey,
  exportSecretKey,
  exportWrappingKey,
  generatePublicKeyPairV3,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV3,
  importSecretKeyV3,
  importWrappingKey,
  publicPaserkIdLegacy,
  publicKeyFromCryptoKeyV3,
  publicKeyToCryptoKey,
  secretPaserkIdLegacy,
  secretKeyFromCryptoKeyV3,
  secretKeyToCryptoKey,
  signPublicV3,
  unwrapSecretKeyLegacy,
  unwrapSecretKeyWithPasswordLegacy,
  verifyPublicV3,
  wrapSecretKeyLegacy,
  wrapSecretKeyWithPasswordLegacy,
} from '../_internal/operations.ts'

/**
 * Verification key used by the built-in v3.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v3.public' }
  readonly type: 'public'
  readonly version: 3
  readonly kind: 'public'
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
export async function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey> {
  return await publicKeyFromCryptoKeyV3(key)
}

/**
 * Returns the native ECDSA P-384 public key retained by a built-in v3.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v3.public key
 */
export function PublicKeyToCryptoKey(key: PublicKey): CryptoKey {
  return publicKeyToCryptoKey(3, key)
}

/**
 * Signing key used by the built-in v3.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v3.public' }
  readonly type: 'secret'
  readonly version: 3
  readonly kind: 'secret'
}

/**
 * Wrapping key used by the built-in k3.secret-wrap.pie implementation.
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
 * Wraps a native ECDSA P-384 private key for use with the built-in v3.public capabilities.
 *
 * The key usages must include `sign`. The exact private-key instance is retained. Its public key is
 * obtained with `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native ECDSA P-384 private key
 */
export async function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey> {
  return await secretKeyFromCryptoKeyV3(key)
}

/**
 * Returns the native ECDSA private key retained by a built-in v3.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v3.public secret key
 */
export function SecretKeyToCryptoKey(key: SecretKey): CryptoKey {
  return secretKeyToCryptoKey(3, key)
}

/**
 * Built-in v3.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyPairFactory: ReturnType<
  typeof PublicGenerateKeyPair<3, PublicKey, SecretKey>
> = /* @__PURE__ */ PublicGenerateKeyPair<3, PublicKey, SecretKey>({
  version: 3,
  run: generatePublicKeyPairV3,
})

/**
 * Built-in v3.public token-signing capability factory.
 *
 * @category Token Operations
 */
export const SignFactory: ReturnType<typeof PublicSign<3, SecretKey>> = /* @__PURE__ */ PublicSign<
  3,
  SecretKey
>({ version: 3, run: signPublicV3 })

/**
 * Built-in v3.public token-verification capability factory.
 *
 * @category Token Operations
 */
export const VerifyFactory: ReturnType<typeof PublicVerify<3, PublicKey>> =
  /* @__PURE__ */ PublicVerify<3, PublicKey>({ version: 3, run: verifyPublicV3 })

/**
 * Built-in PASERK k3.public key-import capability factory.
 *
 * @category Key Management
 */
export const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<3, PublicKey>> =
  /* @__PURE__ */ PublicImportPublicKey<3, PublicKey>({ version: 3, run: importPublicKeyV3 })

/**
 * Built-in PASERK k3.public key-export capability factory.
 *
 * @category Key Management
 */
export const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<3, PublicKey>> =
  /* @__PURE__ */ PublicExportPublicKey<3, PublicKey>({
    version: 3,
    run: (key) => exportPublicKey(3, key),
  })

/**
 * Built-in PASERK k3.secret key-import capability factory.
 *
 * @category Key Management
 */
export const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<3, SecretKey>> =
  /* @__PURE__ */ PublicImportSecretKey<3, SecretKey>({ version: 3, run: importSecretKeyV3 })

/**
 * Built-in PASERK k3.secret key-export capability factory.
 *
 * @category Key Management
 */
export const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<3, SecretKey>> =
  /* @__PURE__ */ PublicExportSecretKey<3, SecretKey>({
    version: 3,
    run: (key) => exportSecretKey(3, key),
  })

/**
 * Built-in PASERK k3 public-key derivation capability factory.
 *
 * @category Key Management
 */
export const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<3, PublicKey, SecretKey>> =
  /* @__PURE__ */ PublicGetPublicKey<3, PublicKey, SecretKey>({
    version: 3,
    run: (key) => getPublicKey(3, key),
  })

/**
 * Built-in PASERK k3.pid identifier capability factory.
 *
 * @category Key Management
 */
export const PublicKeyIDFactory: ReturnType<typeof PublicKeyID<3>> = /* @__PURE__ */ PublicKeyID<3>(
  { version: 3, run: (paserk) => publicPaserkIdLegacy(3, paserk) },
)

/**
 * Built-in PASERK k3.sid identifier capability factory.
 *
 * @category Key Management
 */
export const SecretKeyIDFactory: ReturnType<typeof SecretKeyID<3>> = /* @__PURE__ */ SecretKeyID<3>(
  { version: 3, run: (paserk) => secretPaserkIdLegacy(3, paserk) },
)

/**
 * Built-in PASERK k3 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof PublicGenerateWrappingKey<3, WrappingKey>
> = /* @__PURE__ */ PublicGenerateWrappingKey<3, WrappingKey>({
  version: 3,
  run: (extractable) => generateWrappingKey(3, extractable),
})

/**
 * Built-in PASERK k3 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<3, WrappingKey>> =
  /* @__PURE__ */ PublicImportWrappingKey<3, WrappingKey>({
    version: 3,
    run: (material, extractable) => importWrappingKey(3, material, extractable),
  })

/**
 * Built-in PASERK k3 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<3, WrappingKey>> =
  /* @__PURE__ */ PublicExportWrappingKey<3, WrappingKey>({
    version: 3,
    run: (key) => exportWrappingKey(3, key),
  })

/**
 * Built-in PASERK k3.secret-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export const WrapSecretKeyFactory: ReturnType<
  typeof PublicWrapSecretKey<3, SecretKey, WrappingKey, 'pie'>
> = /* @__PURE__ */ PublicWrapSecretKey<3, SecretKey, WrappingKey, 'pie'>({
  version: 3,
  run: (key, wrappingKey) => wrapSecretKeyLegacy(3, key, wrappingKey),
})

/**
 * Built-in PASERK k3.secret-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export const UnwrapSecretKeyFactory: ReturnType<
  typeof PublicUnwrapSecretKey<3, SecretKey, WrappingKey, 'pie'>
> = /* @__PURE__ */ PublicUnwrapSecretKey<3, SecretKey, WrappingKey, 'pie'>({
  version: 3,
  run: (paserk, wrappingKey, extractable) =>
    unwrapSecretKeyLegacy(3, paserk, wrappingKey, extractable),
})

/**
 * Built-in PASERK k3.secret-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const WrapSecretKeyWithPasswordFactory: ReturnType<
  typeof PublicWrapSecretKeyWithPassword<3, SecretKey>
> = /* @__PURE__ */ PublicWrapSecretKeyWithPassword<3, SecretKey>({
  version: 3,
  run: (key, password, options) => wrapSecretKeyWithPasswordLegacy(3, key, password, options ?? {}),
})

/**
 * Built-in PASERK k3.secret-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const UnwrapSecretKeyWithPasswordFactory: ReturnType<
  typeof PublicUnwrapSecretKeyWithPassword<3, SecretKey>
> = /* @__PURE__ */ PublicUnwrapSecretKeyWithPassword<3, SecretKey>({
  version: 3,
  run: (paserk, password, limits, extractable) =>
    unwrapSecretKeyWithPasswordLegacy(3, paserk, password, limits, extractable),
})
