/**
 * Built-in PASETO and PASERK v1.public capability factories and CryptoKey adapters backed by
 * standard runtime APIs.
 *
 * @module v1/public
 * @category Public Implementations
 * @categoryDescription Token Operations
 * Factories for signing and verifying v1.public tokens.
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
  generatePublicKeyPairV1,
  generateWrappingKey,
  getPublicKey,
  importPublicKeyV1,
  importSecretKeyV1,
  importWrappingKey,
  publicPaserkIdLegacy,
  publicKeyFromCryptoKeyV1,
  publicKeyToCryptoKey,
  secretPaserkIdLegacy,
  secretKeyFromCryptoKeyV1,
  secretKeyToCryptoKey,
  signPublicV1,
  unwrapSecretKeyLegacy,
  unwrapSecretKeyWithPasswordLegacy,
  verifyPublicV1,
  wrapSecretKeyLegacy,
  wrapSecretKeyWithPasswordLegacy,
} from '../_internal/operations.ts'

/**
 * Verification key used by the built-in v1.public implementations.
 *
 * @category Key Management
 */
export interface PublicKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v1.public' }
  readonly type: 'public'
  readonly version: 1
  readonly kind: 'public'
}

/**
 * Wraps a native RSA-PSS public key for use with the built-in v1.public capabilities.
 *
 * The key must use SHA-384, a 2048-bit modulus, exponent 65537, and include the `verify` usage. The
 * exact public-key instance is retained, including when it is non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Native RSA-PSS public key
 */
export async function PublicKeyFromCryptoKey(key: CryptoKey): Promise<PublicKey> {
  return await publicKeyFromCryptoKeyV1(key)
}

/**
 * Returns the native RSA-PSS public key retained by a built-in v1.public key.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v1.public key
 */
export function PublicKeyToCryptoKey(key: PublicKey): CryptoKey {
  return publicKeyToCryptoKey(1, key)
}

/**
 * Signing key used by the built-in v1.public implementations.
 *
 * @category Key Management
 */
export interface SecretKey extends Key {
  readonly algorithm: { readonly name: 'PASETO v1.public' }
  readonly type: 'secret'
  readonly version: 1
  readonly kind: 'secret'
}

/**
 * Wrapping key used by the built-in k1.secret-wrap.pie implementation.
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
 * Wraps a native RSA-PSS private key for use with the built-in v1.public capabilities.
 *
 * The key must use SHA-384, a 2048-bit modulus, exponent 65537, and include the `sign` usage. The
 * exact private-key instance is retained. Its public key is obtained with
 * `SubtleCrypto.getPublicKey()` or, when extractable, by exporting its JWK.
 *
 * @category CryptoKey Adapters
 * @param key - Native RSA-PSS private key
 */
export async function SecretKeyFromCryptoKey(key: CryptoKey): Promise<SecretKey> {
  return await secretKeyFromCryptoKeyV1(key)
}

/**
 * Returns the native RSA-PSS private key retained by a built-in v1.public secret key.
 *
 * This returns a key handle and does not export key material. A non-extractable key remains
 * non-extractable.
 *
 * @category CryptoKey Adapters
 * @param key - Built-in v1.public secret key
 */
export function SecretKeyToCryptoKey(key: SecretKey): CryptoKey {
  return secretKeyToCryptoKey(1, key)
}

/**
 * Built-in v1.public signing-key-pair generation capability factory.
 *
 * @category Key Management
 */
export const GenerateKeyPairFactory: ReturnType<
  typeof PublicGenerateKeyPair<1, PublicKey, SecretKey>
> = /* @__PURE__ */ PublicGenerateKeyPair<1, PublicKey, SecretKey>({
  version: 1,
  run: generatePublicKeyPairV1,
})

/**
 * Built-in v1.public token-signing capability factory.
 *
 * @category Token Operations
 */
export const SignFactory: ReturnType<typeof PublicSign<1, SecretKey>> = /* @__PURE__ */ PublicSign<
  1,
  SecretKey
>({ version: 1, run: signPublicV1 })

/**
 * Built-in v1.public token-verification capability factory.
 *
 * @category Token Operations
 */
export const VerifyFactory: ReturnType<typeof PublicVerify<1, PublicKey>> =
  /* @__PURE__ */ PublicVerify<1, PublicKey>({ version: 1, run: verifyPublicV1 })

/**
 * Built-in PASERK k1.public key-import capability factory.
 *
 * @category Key Management
 */
export const ImportPublicKeyFactory: ReturnType<typeof PublicImportPublicKey<1, PublicKey>> =
  /* @__PURE__ */ PublicImportPublicKey<1, PublicKey>({ version: 1, run: importPublicKeyV1 })

/**
 * Built-in PASERK k1.public key-export capability factory.
 *
 * @category Key Management
 */
export const ExportPublicKeyFactory: ReturnType<typeof PublicExportPublicKey<1, PublicKey>> =
  /* @__PURE__ */ PublicExportPublicKey<1, PublicKey>({
    version: 1,
    run: (key) => exportPublicKey(1, key),
  })

/**
 * Built-in PASERK k1.secret key-import capability factory.
 *
 * @category Key Management
 */
export const ImportSecretKeyFactory: ReturnType<typeof PublicImportSecretKey<1, SecretKey>> =
  /* @__PURE__ */ PublicImportSecretKey<1, SecretKey>({ version: 1, run: importSecretKeyV1 })

/**
 * Built-in PASERK k1.secret key-export capability factory.
 *
 * @category Key Management
 */
export const ExportSecretKeyFactory: ReturnType<typeof PublicExportSecretKey<1, SecretKey>> =
  /* @__PURE__ */ PublicExportSecretKey<1, SecretKey>({
    version: 1,
    run: (key) => exportSecretKey(1, key),
  })

/**
 * Built-in PASERK k1 public-key derivation capability factory.
 *
 * @category Key Management
 */
export const GetPublicKeyFactory: ReturnType<typeof PublicGetPublicKey<1, PublicKey, SecretKey>> =
  /* @__PURE__ */ PublicGetPublicKey<1, PublicKey, SecretKey>({
    version: 1,
    run: (key) => getPublicKey(1, key),
  })

/**
 * Built-in PASERK k1.pid identifier capability factory.
 *
 * @category Key Management
 */
export const PublicKeyIDFactory: ReturnType<typeof PublicKeyID<1>> = /* @__PURE__ */ PublicKeyID<1>(
  { version: 1, run: (paserk) => publicPaserkIdLegacy(1, paserk) },
)

/**
 * Built-in PASERK k1.sid identifier capability factory.
 *
 * @category Key Management
 */
export const SecretKeyIDFactory: ReturnType<typeof SecretKeyID<1>> = /* @__PURE__ */ SecretKeyID<1>(
  { version: 1, run: (paserk) => secretPaserkIdLegacy(1, paserk) },
)

/**
 * Built-in PASERK k1 wrapping-key generation capability factory.
 *
 * @category Key Wrapping
 */
export const GenerateWrappingKeyFactory: ReturnType<
  typeof PublicGenerateWrappingKey<1, WrappingKey>
> = /* @__PURE__ */ PublicGenerateWrappingKey<1, WrappingKey>({
  version: 1,
  run: (extractable) => generateWrappingKey(1, extractable),
})

/**
 * Built-in PASERK k1 wrapping-key import capability factory.
 *
 * @category Key Wrapping
 */
export const ImportWrappingKeyFactory: ReturnType<typeof PublicImportWrappingKey<1, WrappingKey>> =
  /* @__PURE__ */ PublicImportWrappingKey<1, WrappingKey>({
    version: 1,
    run: (material, extractable) => importWrappingKey(1, material, extractable),
  })

/**
 * Built-in PASERK k1 wrapping-key export capability factory.
 *
 * @category Key Wrapping
 */
export const ExportWrappingKeyFactory: ReturnType<typeof PublicExportWrappingKey<1, WrappingKey>> =
  /* @__PURE__ */ PublicExportWrappingKey<1, WrappingKey>({
    version: 1,
    run: (key) => exportWrappingKey(1, key),
  })

/**
 * Built-in PASERK k1.secret-wrap.pie wrapping capability factory.
 *
 * @category Key Wrapping
 */
export const WrapSecretKeyFactory: ReturnType<
  typeof PublicWrapSecretKey<1, SecretKey, WrappingKey, 'pie'>
> = /* @__PURE__ */ PublicWrapSecretKey<1, SecretKey, WrappingKey, 'pie'>({
  version: 1,
  run: (key, wrappingKey) => wrapSecretKeyLegacy(1, key, wrappingKey),
})

/**
 * Built-in PASERK k1.secret-wrap.pie unwrapping capability factory.
 *
 * @category Key Wrapping
 */
export const UnwrapSecretKeyFactory: ReturnType<
  typeof PublicUnwrapSecretKey<1, SecretKey, WrappingKey, 'pie'>
> = /* @__PURE__ */ PublicUnwrapSecretKey<1, SecretKey, WrappingKey, 'pie'>({
  version: 1,
  run: (paserk, wrappingKey, extractable) =>
    unwrapSecretKeyLegacy(1, paserk, wrappingKey, extractable),
})

/**
 * Built-in PASERK k1.secret-pw wrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const WrapSecretKeyWithPasswordFactory: ReturnType<
  typeof PublicWrapSecretKeyWithPassword<1, SecretKey>
> = /* @__PURE__ */ PublicWrapSecretKeyWithPassword<1, SecretKey>({
  version: 1,
  run: (key, password, options) => wrapSecretKeyWithPasswordLegacy(1, key, password, options ?? {}),
})

/**
 * Built-in PASERK k1.secret-pw unwrapping capability factory.
 *
 * @category Password-Based Key Wrapping
 */
export const UnwrapSecretKeyWithPasswordFactory: ReturnType<
  typeof PublicUnwrapSecretKeyWithPassword<1, SecretKey>
> = /* @__PURE__ */ PublicUnwrapSecretKeyWithPassword<1, SecretKey>({
  version: 1,
  run: (paserk, password, limits, extractable) =>
    unwrapSecretKeyWithPasswordLegacy(1, paserk, password, limits, extractable),
})
