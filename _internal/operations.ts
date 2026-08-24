import {
  InvalidKeyError,
  InvalidPASERKError,
  type CryptoKey,
  type LocalIdPASERK,
  type KeyPair,
  type LocalPASERK,
  type PasswordUnwrapLimits,
  type PasswordWrapOptions,
  type PasswordWrappedLocalPASERK,
  type PasswordWrappedSecretPASERK,
  type PublicIdPASERK,
  type PublicPASERK,
  type SealedLocalPASERK,
  type SecretIdPASERK,
  type SecretPASERK,
  type Version,
  type WrappedLocalPASERK,
  type WrappedSecretPASERK,
} from '../index.ts'

import {
  ascii,
  checkBytes,
  concat,
  copyBytes,
  decodeBase64url,
  decodeUtf8,
  equalBytes,
  positiveInteger,
  randomBytes,
  readUint32be,
  toB64u,
  uint32be,
} from './bytes.ts'
import {
  aesCtr,
  assertLocalCryptoKey,
  compressP384,
  decryptV1Local,
  decryptV3Local,
  digest,
  encryptV1Local,
  encryptV3Local,
  generateEd25519KeyPair,
  generateP384KeyPair,
  generateRsaKeyPair,
  hmacSha384,
  importEd25519SecretCryptoKey,
  importEd25519PublicCryptoKey,
  importLocalCryptoKey,
  importEd25519PublicKey,
  importEd25519SecretKey,
  importP384SecretCryptoKey,
  importP384PublicCryptoKey,
  importP384PublicKey,
  importP384SecretKey,
  importRsaSecretCryptoKey,
  importRsaPublicCryptoKey,
  importRsaPublicKey,
  importRsaSecretKey,
  jwkBytes,
  p384PrivateCryptoKey,
  p384PublicCryptoKey,
  p384RawPublicFromSecret,
  pbkdf2Sha384,
  pemToDer,
  signV1Public,
  signV2Public,
  signV3Public,
  signV4Public,
  verifyV1Public,
  verifyV2Public,
  verifyV3Public,
  verifyV4Public,
  webCryptoOperation,
} from './crypto.ts'
import {
  LocalKeyImpl,
  PublicKeyImpl,
  SealingPublicKeyImpl,
  SealingSecretKeyImpl,
  WrappingKeyImpl,
  localKeyData,
  publicKeyData,
  requireExtractable,
  sealingPublicKeyData,
  sealingSecretKeyData,
  secretKeyData,
  wrappingKeyData,
  type KeyData,
  type LocalKey,
  type LocalKeyData,
  type PublicKey,
  type SealingPublicKey,
  type SealingSecretKey,
  type SecretKey,
  type SealingSecretKeyData,
  type WrappingKey,
} from './keys.ts'

type PaserkKeyType = 'local' | 'public' | 'secret'
type PaserkIdType = 'lid' | 'pid' | 'sid'
type PaserkProtectedType = 'local-wrap.pie' | 'secret-wrap.pie' | 'local-pw' | 'secret-pw' | 'seal'

type LocalIdInput<V extends Version> =
  | LocalPASERK<V>
  | PasswordWrappedLocalPASERK<V>
  | SealedLocalPASERK<V>
  | `k${V}.local-wrap.${string}.${string}`
type SecretIdInput<V extends Version> =
  SecretPASERK<V> | PasswordWrappedSecretPASERK<V> | `k${V}.secret-wrap.${string}.${string}`

function paserkHeader(
  version: Version,
  type: PaserkKeyType | PaserkIdType | PaserkProtectedType,
): string {
  return `k${version}.${type}.`
}

function serializePaserk<V extends Version>(
  version: V,
  type: PaserkKeyType | PaserkProtectedType,
  material: Uint8Array,
): string {
  return `${paserkHeader(version, type)}${toB64u(material)}`
}

function parsePaserk(
  input: string,
  version: Version,
  type: PaserkKeyType | PaserkProtectedType,
): Uint8Array {
  if (typeof input !== 'string') throw new TypeError('"paserk" must be a string')
  const header = paserkHeader(version, type)
  if (!input.startsWith(header) || input.slice(header.length).includes('.')) {
    throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  }
  return decodePaserkPayload(input.slice(header.length))
}

function decodePaserkPayload(input: string): Uint8Array {
  try {
    return decodeBase64url(input, 'PASERK payload')
  } catch (cause) {
    throw new InvalidPASERKError('Invalid PASERK payload', { cause })
  }
}

async function importPaserkKey<K>(
  input: string,
  version: Version,
  type: 'public' | 'secret',
  importKey: (material: Uint8Array) => Promise<K>,
): Promise<K> {
  const material = parsePaserk(input, version, type)
  try {
    return await importKey(material)
  } catch (cause) {
    if (cause instanceof TypeError) {
      throw new InvalidKeyError(`Invalid k${version}.${type} key material`, { cause })
    }
    throw cause
  }
}

async function paserkIdSha384(version: 1 | 3, type: PaserkIdType, paserk: string): Promise<string> {
  const header = paserkHeader(version, type)
  const input = ascii(`${header}${paserk}`)
  const identifier = (await digest('SHA-384', input)).subarray(0, 33)
  return `${header}${toB64u(identifier)}`
}

function standardPaserkIdInput(
  version: Version,
  type: PaserkKeyType | Exclude<PaserkProtectedType, 'local-wrap.pie' | 'secret-wrap.pie'>,
  paserk: string,
): boolean {
  const header = paserkHeader(version, type)
  if (!paserk.startsWith(header)) return false
  const payload = paserk.slice(header.length)
  if (payload === '' || payload.includes('.')) return false
  decodePaserkPayload(payload)
  return true
}

function wrappedPaserkIdInput(
  version: Version,
  type: 'local-wrap' | 'secret-wrap',
  paserk: string,
): boolean {
  const header = `k${version}.${type}.`
  if (!paserk.startsWith(header)) return false
  const data = paserk.slice(header.length)
  const delimiter = data.indexOf('.')
  if (delimiter < 1) return false
  const prefix = data.slice(0, delimiter)
  const encryptedKey = data.slice(delimiter + 1)
  return /^[a-z0-9-]+$/u.test(prefix) && encryptedKey !== '' && /^[\x00-\x7f]+$/u.test(encryptedKey)
}

function validateLocalPaserkIdInput(version: Version, paserk: string): void {
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (
    !standardPaserkIdInput(version, 'local', paserk) &&
    !standardPaserkIdInput(version, 'local-pw', paserk) &&
    !standardPaserkIdInput(version, 'seal', paserk) &&
    !wrappedPaserkIdInput(version, 'local-wrap', paserk)
  ) {
    throw new InvalidPASERKError(
      `Expected a PASERK compatible with ${paserkHeader(version, 'lid')}`,
    )
  }
}

function validatePublicPaserkIdInput(version: Version, paserk: string): void {
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (!standardPaserkIdInput(version, 'public', paserk)) {
    throw new InvalidPASERKError(
      `Expected a PASERK compatible with ${paserkHeader(version, 'pid')}`,
    )
  }
}

function validateSecretPaserkIdInput(version: Version, paserk: string): void {
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (
    !standardPaserkIdInput(version, 'secret', paserk) &&
    !standardPaserkIdInput(version, 'secret-pw', paserk) &&
    !wrappedPaserkIdInput(version, 'secret-wrap', paserk)
  ) {
    throw new InvalidPASERKError(
      `Expected a PASERK compatible with ${paserkHeader(version, 'sid')}`,
    )
  }
}

async function wrapPieSha384(
  version: 1 | 3,
  type: 'local-wrap.pie' | 'secret-wrap.pie',
  plaintext: Uint8Array,
  wrappingKey: Uint8Array,
): Promise<string> {
  const header = ascii(paserkHeader(version, type))
  const nonce = randomBytes(32)
  const temporary = await hmacSha384(wrappingKey, concat(Uint8Array.of(0x80), nonce))
  // The official k1/k3 vectors use a 32-byte authentication key here.
  const authenticationKey = (
    await hmacSha384(wrappingKey, concat(Uint8Array.of(0x81), nonce))
  ).subarray(0, 32)
  const ciphertext = await aesCtr(
    'encrypt',
    temporary.subarray(0, 32),
    temporary.subarray(32),
    plaintext,
  )
  const tag = await hmacSha384(authenticationKey, concat(header, nonce, ciphertext))
  return serializePaserk(version, type, concat(tag, nonce, ciphertext))
}

async function unwrapPieSha384(
  version: 1 | 3,
  type: 'local-wrap.pie' | 'secret-wrap.pie',
  serialized: string,
  wrappingKey: Uint8Array,
  expectedPlaintext: number | undefined,
): Promise<Uint8Array> {
  const input = parsePaserk(serialized, version, type)
  const minimum = 48 + 32 + (expectedPlaintext ?? 1)
  if (
    input.byteLength < minimum ||
    (expectedPlaintext !== undefined && input.byteLength !== minimum)
  ) {
    throw new InvalidPASERKError('Invalid wrapped PASERK length')
  }
  const tag = input.subarray(0, 48)
  const nonce = input.subarray(48, 80)
  const ciphertext = input.subarray(80)
  const header = ascii(paserkHeader(version, type))
  // The official k1/k3 vectors use a 32-byte authentication key here.
  const authenticationKey = (
    await hmacSha384(wrappingKey, concat(Uint8Array.of(0x81), nonce))
  ).subarray(0, 32)
  const expected = await hmacSha384(authenticationKey, concat(header, nonce, ciphertext))
  if (!equalBytes(tag, expected))
    throw new InvalidPASERKError('Wrapped PASERK authentication failed')
  const temporary = await hmacSha384(wrappingKey, concat(Uint8Array.of(0x80), nonce))
  return await aesCtr('decrypt', temporary.subarray(0, 32), temporary.subarray(32), ciphertext)
}

async function wrapPasswordSha384(
  version: 1 | 3,
  type: 'local-pw' | 'secret-pw',
  plaintext: Uint8Array,
  password: Uint8Array,
  options: PasswordWrapOptions<1 | 3>,
): Promise<string> {
  checkBytes(password, 'password')
  if (password.byteLength === 0) throw new TypeError('"password" must not be empty')
  const header = ascii(paserkHeader(version, type))
  const iterations = positiveInteger(options.iterations ?? 100_000, 'iterations')
  const salt = randomBytes(32)
  const nonce = randomBytes(16)
  const preKey = await pbkdf2Sha384(password, salt, iterations, 32)
  const encryptionKey = (await digest('SHA-384', concat(Uint8Array.of(0xff), preKey))).subarray(
    0,
    32,
  )
  const authenticationKey = await digest('SHA-384', concat(Uint8Array.of(0xfe), preKey))
  const ciphertext = await aesCtr('encrypt', encryptionKey, nonce, plaintext)
  const encodedIterations = uint32be(iterations)
  const tag = await hmacSha384(
    authenticationKey,
    concat(header, salt, encodedIterations, nonce, ciphertext),
  )
  return serializePaserk(version, type, concat(salt, encodedIterations, nonce, ciphertext, tag))
}

async function unwrapPasswordSha384(
  version: 1 | 3,
  type: 'local-pw' | 'secret-pw',
  serialized: string,
  password: Uint8Array,
  limits: PasswordUnwrapLimits<1 | 3>,
  expectedPlaintext: number | undefined,
): Promise<Uint8Array> {
  checkBytes(password, 'password')
  if (password.byteLength === 0) throw new TypeError('"password" must not be empty')
  const input = parsePaserk(serialized, version, type)
  const header = ascii(paserkHeader(version, type))
  const minimum = 32 + 4 + 16 + (expectedPlaintext ?? 1) + 48
  if (
    input.byteLength < minimum ||
    (expectedPlaintext !== undefined && input.byteLength !== minimum)
  ) {
    throw new InvalidPASERKError('Invalid password-wrapped PASERK length')
  }
  const salt = input.subarray(0, 32)
  const iterations = readUint32be(input, 32)
  const nonce = input.subarray(36, 52)
  const ciphertext = input.subarray(52, -48)
  const tag = input.subarray(-48)
  const maximum = positiveInteger(limits.maxIterations ?? 1_000_000, 'maxIterations')
  if (iterations === 0 || iterations > maximum) {
    throw new InvalidPASERKError('PBKDF2 iteration count exceeds configured limit')
  }
  const preKey = await pbkdf2Sha384(password, salt, iterations, 32)
  const authenticationKey = await digest('SHA-384', concat(Uint8Array.of(0xfe), preKey))
  const expected = await hmacSha384(
    authenticationKey,
    concat(header, salt, uint32be(iterations), nonce, ciphertext),
  )
  if (!equalBytes(tag, expected))
    throw new InvalidPASERKError('Password-wrapped PASERK authentication failed')
  const encryptionKey = (await digest('SHA-384', concat(Uint8Array.of(0xff), preKey))).subarray(
    0,
    32,
  )
  return await aesCtr('decrypt', encryptionKey, nonce, ciphertext)
}

// ============================================================================
// PASERK public-key encryption (`seal`)
// ============================================================================

async function deriveP384SharedSecret(
  privateKey: CryptoKey,
  publicMaterial: Uint8Array,
): Promise<Uint8Array> {
  const publicKey = await p384PublicCryptoKey(publicMaterial, 'ECDH', [])
  return new Uint8Array(
    await webCryptoOperation('ECDH with P-384', () =>
      crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 384),
    ),
  )
}

async function generateP384Ephemeral(): Promise<{
  privateKey: CryptoKey
  publicMaterial: Uint8Array
}> {
  const pair = await webCryptoOperation(
    'ECDH with P-384',
    () =>
      crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, [
        'deriveBits',
      ]) as Promise<CryptoKeyPair>,
  )
  const raw = new Uint8Array(
    await webCryptoOperation('ECDH with P-384', () =>
      crypto.subtle.exportKey('raw', pair.publicKey),
    ),
  )
  return { privateKey: pair.privateKey, publicMaterial: compressP384(raw) }
}

async function sealV3LocalKey(plaintext: Uint8Array, recipient: KeyData<3>): Promise<string> {
  const header = ascii(paserkHeader(3, 'seal'))
  const ephemeral = await generateP384Ephemeral()
  const shared = await deriveP384SharedSecret(ephemeral.privateKey, recipient.material)
  const temporary = await digest(
    'SHA-384',
    concat(Uint8Array.of(0x01), header, shared, ephemeral.publicMaterial, recipient.material),
  )
  const authenticationKey = await digest(
    'SHA-384',
    concat(Uint8Array.of(0x02), header, shared, ephemeral.publicMaterial, recipient.material),
  )
  const ciphertext = await aesCtr(
    'encrypt',
    temporary.subarray(0, 32),
    temporary.subarray(32),
    plaintext,
  )
  const tag = await hmacSha384(
    authenticationKey,
    concat(header, ephemeral.publicMaterial, ciphertext),
  )
  return serializePaserk(3, 'seal', concat(tag, ephemeral.publicMaterial, ciphertext))
}

async function unsealV3LocalKey(
  serialized: string,
  recipient: SealingSecretKeyData<3>,
): Promise<Uint8Array> {
  const input = parsePaserk(serialized, 3, 'seal')
  if (input.byteLength !== 48 + 49 + 32) {
    throw new InvalidPASERKError('Invalid sealed PASERK length')
  }
  const tag = input.subarray(0, 48)
  const ephemeralPublic = input.subarray(48, 97)
  const ciphertext = input.subarray(97)
  const header = ascii(paserkHeader(3, 'seal'))
  const privateKey = await p384PrivateCryptoKey(recipient, 'ECDH', 'deriveBits')
  let shared: Uint8Array
  try {
    shared = await deriveP384SharedSecret(privateKey, ephemeralPublic)
  } catch (cause) {
    if (cause instanceof InvalidKeyError) {
      throw new InvalidPASERKError('Invalid sealed PASERK ephemeral public key', { cause })
    }
    throw cause
  }
  const authenticationKey = await digest(
    'SHA-384',
    concat(Uint8Array.of(0x02), header, shared, ephemeralPublic, recipient.publicMaterial),
  )
  const expected = await hmacSha384(authenticationKey, concat(header, ephemeralPublic, ciphertext))
  if (!equalBytes(tag, expected)) {
    throw new InvalidPASERKError('Sealed PASERK authentication failed')
  }
  const temporary = await digest(
    'SHA-384',
    concat(Uint8Array.of(0x01), header, shared, ephemeralPublic, recipient.publicMaterial),
  )
  return await aesCtr('decrypt', temporary.subarray(0, 32), temporary.subarray(32), ciphertext)
}

// ============================================================================
// Fixed version/purpose APIs
// ============================================================================

function wrappingKey<V extends Version>(
  version: V,
  material: Uint8Array,
  extractable: boolean,
): WrappingKey<V> {
  checkBytes(material, 'material', 32)
  return new WrappingKeyImpl(version, material, extractable)
}

function normalizeWrappedRsaSecret(material: Uint8Array): Uint8Array {
  try {
    const value = decodeUtf8(material)
    if (value.startsWith('-----BEGIN RSA PRIVATE KEY-----')) return pemToDer(value)
  } catch {
    // Binary DER is the canonical k1.secret representation.
  }
  return material
}

function localMaterial(data: LocalKeyData<Version>): Uint8Array {
  if (data.material === undefined) throw new InvalidKeyError('Key material is not available')
  return data.material
}

function secretMaterial(data: { readonly material: Uint8Array | undefined }): Uint8Array {
  if (data.material === undefined) throw new InvalidKeyError('Key material is not available')
  return data.material
}

function secretPublicMaterial(data: {
  readonly publicMaterial: Uint8Array | undefined
}): Uint8Array {
  if (data.publicMaterial === undefined) {
    throw new InvalidKeyError('Public key material is not available')
  }
  return data.publicMaterial
}

function publicMaterial(data: { readonly material: Uint8Array | undefined }): Uint8Array {
  if (data.material === undefined) throw new InvalidKeyError('Public key material is not available')
  return data.material
}

async function localKeyFromMaterialLegacy<V extends 1 | 3>(
  version: V,
  material: Uint8Array,
  extractable: boolean,
): Promise<LocalKey<V>> {
  const cryptoKey = await importLocalCryptoKey(material)
  return new LocalKeyImpl(version, extractable ? material : undefined, extractable, cryptoKey)
}

function localKeyFromMaterialModern<V extends 2 | 4>(
  version: V,
  material: Uint8Array,
  extractable: boolean,
): LocalKey<V> {
  return new LocalKeyImpl(version, material, extractable)
}

/** Wraps a native HKDF key for a built-in v1.local or v3.local implementation. */
export function localKeyFromCryptoKey<V extends 1 | 3>(version: V, key: CryptoKey): LocalKey<V> {
  assertLocalCryptoKey(key)
  return new LocalKeyImpl(version, undefined, key.extractable, key)
}

/** Returns the native HKDF key retained by a built-in v1.local or v3.local key. */
export function localKeyToCryptoKey<V extends 1 | 3>(version: V, key: LocalKey<V>): CryptoKey {
  const cryptoKey = localKeyData(key, version).cryptoKey
  if (cryptoKey === undefined) throw new InvalidKeyError('Key is not backed by a CryptoKey')
  return cryptoKey
}

/** Wraps a native RSA-PSS public key for the built-in v1.public implementation. */
export async function publicKeyFromCryptoKeyV1(key: CryptoKey): Promise<PublicKey<1>> {
  return await importRsaPublicCryptoKey(key)
}

/** Wraps a native Ed25519 public key for the built-in v2.public implementation. */
export async function publicKeyFromCryptoKeyV2(key: CryptoKey): Promise<PublicKey<2>> {
  return await importEd25519PublicCryptoKey(2, key)
}

/** Wraps a native ECDSA P-384 public key for the built-in v3.public implementation. */
export async function publicKeyFromCryptoKeyV3(key: CryptoKey): Promise<PublicKey<3>> {
  return await importP384PublicCryptoKey(key)
}

/** Wraps a native Ed25519 public key for the built-in v4.public implementation. */
export async function publicKeyFromCryptoKeyV4(key: CryptoKey): Promise<PublicKey<4>> {
  return await importEd25519PublicCryptoKey(4, key)
}

/** Returns the native public key retained by a built-in public-purpose public key. */
export function publicKeyToCryptoKey<V extends Version>(version: V, key: PublicKey<V>): CryptoKey {
  return publicKeyData(key, version).cryptoKey
}

/** Wraps a native RSA-PSS private key for the built-in v1.public implementation. */
export async function secretKeyFromCryptoKeyV1(key: CryptoKey): Promise<SecretKey<1>> {
  return await importRsaSecretCryptoKey(key)
}

/** Wraps a native Ed25519 private key for the built-in v2.public implementation. */
export async function secretKeyFromCryptoKeyV2(key: CryptoKey): Promise<SecretKey<2>> {
  return await importEd25519SecretCryptoKey(2, key)
}

/** Wraps a native ECDSA P-384 private key for the built-in v3.public implementation. */
export async function secretKeyFromCryptoKeyV3(key: CryptoKey): Promise<SecretKey<3>> {
  return await importP384SecretCryptoKey(key)
}

/** Wraps a native Ed25519 private key for the built-in v4.public implementation. */
export async function secretKeyFromCryptoKeyV4(key: CryptoKey): Promise<SecretKey<4>> {
  return await importEd25519SecretCryptoKey(4, key)
}

/** Returns the native private key retained by a built-in public-purpose secret key. */
export function secretKeyToCryptoKey<V extends Version>(version: V, key: SecretKey<V>): CryptoKey {
  return secretKeyData(key, version).cryptoKey
}

async function generateP384SealingKeyPair(
  extractable: boolean,
): Promise<{ publicKey: SealingPublicKey<3>; secretKey: SealingSecretKey<3> }> {
  const generated = await webCryptoOperation(
    'ECDH with P-384',
    () =>
      crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, [
        'deriveBits',
      ]) as Promise<CryptoKeyPair>,
  )
  const privateJwk = await webCryptoOperation('ECDH with P-384', () =>
    crypto.subtle.exportKey('jwk', generated.privateKey),
  )
  const publicRaw = new Uint8Array(
    await webCryptoOperation('ECDH with P-384', () =>
      crypto.subtle.exportKey('raw', generated.publicKey),
    ),
  )
  const secretMaterial = jwkBytes(privateJwk.d, 'd')
  const publicMaterial = compressP384(publicRaw)
  return {
    publicKey: new SealingPublicKeyImpl(3, publicMaterial),
    secretKey: new SealingSecretKeyImpl(3, secretMaterial, publicMaterial, extractable),
  }
}

async function importP384SealingPublicKey(material: Uint8Array): Promise<SealingPublicKey<3>> {
  checkBytes(material, 'material', 49)
  await p384PublicCryptoKey(material, 'ECDH', [])
  return new SealingPublicKeyImpl(3, material)
}

async function importP384SealingSecretKey(
  material: Uint8Array,
  extractable: boolean,
): Promise<SealingSecretKey<3>> {
  const raw = await p384RawPublicFromSecret(material, 'ECDH', 'deriveBits')
  return new SealingSecretKeyImpl(3, material, compressP384(raw), extractable)
}

export async function generateLocalKeyLegacy<V extends 1 | 3>(
  version: V,
  extractable: boolean,
): Promise<LocalKey<V>> {
  return await localKeyFromMaterialLegacy(version, randomBytes(32), extractable)
}

export async function generateLocalKeyModern<V extends 2 | 4>(
  version: V,
  extractable: boolean,
): Promise<LocalKey<V>> {
  return localKeyFromMaterialModern(version, randomBytes(32), extractable)
}

export async function encryptLocalV1(
  key: LocalKey<1>,
  plaintext: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  const data = localKeyData(key, 1)
  return await encryptV1Local(data.cryptoKey ?? localMaterial(data), plaintext, footer)
}

export async function decryptLocalV1(
  key: LocalKey<1>,
  payload: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  const data = localKeyData(key, 1)
  return await decryptV1Local(data.cryptoKey ?? localMaterial(data), payload, footer)
}

export async function encryptLocalV3(
  key: LocalKey<3>,
  plaintext: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<Uint8Array> {
  const data = localKeyData(key, 3)
  return await encryptV3Local(
    data.cryptoKey ?? localMaterial(data),
    plaintext,
    footer,
    implicitAssertion,
  )
}

export async function decryptLocalV3(
  key: LocalKey<3>,
  payload: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<Uint8Array> {
  const data = localKeyData(key, 3)
  return await decryptV3Local(
    data.cryptoKey ?? localMaterial(data),
    payload,
    footer,
    implicitAssertion,
  )
}

function parseLocalKey<V extends Version>(version: V, paserk: LocalPASERK<V>): Uint8Array {
  const material = parsePaserk(paserk, version, 'local')
  if (material.byteLength !== 32) {
    throw new InvalidKeyError(`Invalid k${version}.local key material`)
  }
  return material
}

export async function importLocalKeyLegacy<V extends 1 | 3>(
  version: V,
  paserk: LocalPASERK<V>,
  extractable: boolean,
): Promise<LocalKey<V>> {
  return await localKeyFromMaterialLegacy(version, parseLocalKey(version, paserk), extractable)
}

export async function importLocalKeyModern<V extends 2 | 4>(
  version: V,
  paserk: LocalPASERK<V>,
  extractable: boolean,
): Promise<LocalKey<V>> {
  return localKeyFromMaterialModern(version, parseLocalKey(version, paserk), extractable)
}

export async function exportLocalKey<V extends Version>(
  version: V,
  key: LocalKey<V>,
): Promise<LocalPASERK<V>> {
  const data = localKeyData(key, version)
  requireExtractable(data)
  return serializePaserk(version, 'local', localMaterial(data)) as LocalPASERK<V>
}

export async function localPaserkIdLegacy<V extends 1 | 3>(
  version: V,
  paserk: LocalIdInput<V>,
): Promise<LocalIdPASERK<V>> {
  validateLocalPaserkIdInput(version, paserk)
  return (await paserkIdSha384(version, 'lid', paserk)) as LocalIdPASERK<V>
}

export async function generateWrappingKey<V extends Version>(
  version: V,
  extractable: boolean,
): Promise<WrappingKey<V>> {
  return wrappingKey(version, randomBytes(32), extractable)
}

export async function importWrappingKey<V extends Version>(
  version: V,
  material: Uint8Array,
  extractable: boolean,
): Promise<WrappingKey<V>> {
  return wrappingKey(version, material, extractable)
}

export async function exportWrappingKey<V extends Version>(
  version: V,
  key: WrappingKey<V>,
): Promise<Uint8Array> {
  const data = wrappingKeyData(key, version)
  requireExtractable(data)
  return copyBytes(data.material)
}

export async function wrapLocalKeyLegacy<V extends 1 | 3>(
  version: V,
  key: LocalKey<V>,
  wrapping: WrappingKey<V>,
): Promise<WrappedLocalPASERK<V, 'pie'>> {
  const source = localKeyData(key, version)
  requireExtractable(source)
  return (await wrapPieSha384(
    version,
    'local-wrap.pie',
    localMaterial(source),
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
  )) as WrappedLocalPASERK<V, 'pie'>
}

export async function unwrapLocalKeyLegacy<V extends 1 | 3>(
  version: V,
  paserk: WrappedLocalPASERK<V, 'pie'>,
  wrapping: WrappingKey<V>,
  extractable: boolean,
): Promise<LocalKey<V>> {
  const material = await unwrapPieSha384(
    version,
    'local-wrap.pie',
    paserk,
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
    32,
  )
  return await localKeyFromMaterialLegacy(version, material, extractable)
}

export async function wrapLocalKeyWithPasswordLegacy<V extends 1 | 3>(
  version: V,
  key: LocalKey<V>,
  password: Uint8Array,
  options: PasswordWrapOptions<V>,
): Promise<PasswordWrappedLocalPASERK<V>> {
  const source = localKeyData(key, version)
  requireExtractable(source)
  return (await wrapPasswordSha384(
    version,
    'local-pw',
    localMaterial(source),
    password,
    options as PasswordWrapOptions<1 | 3>,
  )) as PasswordWrappedLocalPASERK<V>
}

export async function unwrapLocalKeyWithPasswordLegacy<V extends 1 | 3>(
  version: V,
  paserk: PasswordWrappedLocalPASERK<V>,
  password: Uint8Array,
  limits: PasswordUnwrapLimits<V>,
  extractable: boolean,
): Promise<LocalKey<V>> {
  const material = await unwrapPasswordSha384(
    version,
    'local-pw',
    paserk,
    password,
    limits as PasswordUnwrapLimits<1 | 3>,
    32,
  )
  return await localKeyFromMaterialLegacy(version, material, extractable)
}

export async function generateSealingKeyPairV3(
  extractable: boolean,
): Promise<KeyPair<SealingPublicKey<3>, SealingSecretKey<3>>> {
  return await generateP384SealingKeyPair(extractable)
}

export async function importSealingPublicKeyV3(material: Uint8Array): Promise<SealingPublicKey<3>> {
  return await importP384SealingPublicKey(material)
}

export async function importSealingSecretKeyV3(
  material: Uint8Array,
  extractable: boolean,
): Promise<SealingSecretKey<3>> {
  return await importP384SealingSecretKey(material, extractable)
}

export async function exportSealingPublicKeyV3(key: SealingPublicKey<3>): Promise<Uint8Array> {
  return copyBytes(sealingPublicKeyData(key, 3).material)
}

export async function exportSealingSecretKeyV3(key: SealingSecretKey<3>): Promise<Uint8Array> {
  const data = sealingSecretKeyData(key, 3)
  requireExtractable(data)
  return copyBytes(data.material)
}

export async function sealLocalKeyV3(
  key: LocalKey<3>,
  recipient: SealingPublicKey<3>,
): Promise<SealedLocalPASERK<3>> {
  const source = localKeyData(key, 3)
  requireExtractable(source)
  return (await sealV3LocalKey(
    localMaterial(source),
    sealingPublicKeyData(recipient, 3, 'recipient'),
  )) as SealedLocalPASERK<3>
}

export async function unsealLocalKeyV3(
  paserk: SealedLocalPASERK<3>,
  recipient: SealingSecretKey<3>,
  extractable: boolean,
): Promise<LocalKey<3>> {
  const material = await unsealV3LocalKey(paserk, sealingSecretKeyData(recipient, 3))
  checkBytes(material, 'unsealed local key', 32)
  return await localKeyFromMaterialLegacy(3, material, extractable)
}

export async function generatePublicKeyPairV1(
  extractable: boolean,
): Promise<KeyPair<PublicKey<1>, SecretKey<1>>> {
  return await generateRsaKeyPair(extractable)
}

export async function generatePublicKeyPairV2(
  extractable: boolean,
): Promise<KeyPair<PublicKey<2>, SecretKey<2>>> {
  return await generateEd25519KeyPair(2, extractable)
}

export async function generatePublicKeyPairV3(
  extractable: boolean,
): Promise<KeyPair<PublicKey<3>, SecretKey<3>>> {
  return await generateP384KeyPair(extractable)
}

export async function generatePublicKeyPairV4(
  extractable: boolean,
): Promise<KeyPair<PublicKey<4>, SecretKey<4>>> {
  return await generateEd25519KeyPair(4, extractable)
}

export async function signPublicV1(
  key: SecretKey<1>,
  message: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  return await signV1Public(secretKeyData(key, 1), message, footer)
}

export async function verifyPublicV1(
  key: PublicKey<1>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
): Promise<boolean> {
  return await verifyV1Public(publicKeyData(key, 1), message, signature, footer)
}

export async function signPublicV2(
  key: SecretKey<2>,
  message: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  return await signV2Public(secretKeyData(key, 2), message, footer)
}

export async function verifyPublicV2(
  key: PublicKey<2>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
): Promise<boolean> {
  return await verifyV2Public(publicKeyData(key, 2), message, signature, footer)
}

export async function signPublicV3(
  key: SecretKey<3>,
  message: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<Uint8Array> {
  return await signV3Public(secretKeyData(key, 3), message, footer, implicitAssertion)
}

export async function verifyPublicV3(
  key: PublicKey<3>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<boolean> {
  return await verifyV3Public(publicKeyData(key, 3), message, signature, footer, implicitAssertion)
}

export async function signPublicV4(
  key: SecretKey<4>,
  message: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<Uint8Array> {
  return await signV4Public(secretKeyData(key, 4), message, footer, implicitAssertion)
}

export async function verifyPublicV4(
  key: PublicKey<4>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
  implicitAssertion: Uint8Array,
): Promise<boolean> {
  return await verifyV4Public(publicKeyData(key, 4), message, signature, footer, implicitAssertion)
}

export async function importPublicKeyV1(paserk: PublicPASERK<1>): Promise<PublicKey<1>> {
  return await importPaserkKey(paserk, 1, 'public', importRsaPublicKey)
}

export async function importPublicKeyV2(paserk: PublicPASERK<2>): Promise<PublicKey<2>> {
  return await importPaserkKey(paserk, 2, 'public', (material) =>
    importEd25519PublicKey(2, material),
  )
}

export async function importPublicKeyV3(paserk: PublicPASERK<3>): Promise<PublicKey<3>> {
  return await importPaserkKey(paserk, 3, 'public', importP384PublicKey)
}

export async function importPublicKeyV4(paserk: PublicPASERK<4>): Promise<PublicKey<4>> {
  return await importPaserkKey(paserk, 4, 'public', (material) =>
    importEd25519PublicKey(4, material),
  )
}

export async function exportPublicKey<V extends Version>(
  version: V,
  key: PublicKey<V>,
): Promise<PublicPASERK<V>> {
  const data = publicKeyData(key, version)
  requireExtractable(data)
  return serializePaserk(version, 'public', publicMaterial(data)) as PublicPASERK<V>
}

export async function importSecretKeyV1(
  paserk: SecretPASERK<1>,
  extractable: boolean,
): Promise<SecretKey<1>> {
  return await importPaserkKey(paserk, 1, 'secret', (material) =>
    importRsaSecretKey(material, extractable),
  )
}

export async function importSecretKeyV2(
  paserk: SecretPASERK<2>,
  extractable: boolean,
): Promise<SecretKey<2>> {
  return await importPaserkKey(paserk, 2, 'secret', (material) =>
    importEd25519SecretKey(2, material, extractable),
  )
}

export async function importSecretKeyV3(
  paserk: SecretPASERK<3>,
  extractable: boolean,
): Promise<SecretKey<3>> {
  return await importPaserkKey(paserk, 3, 'secret', (material) =>
    importP384SecretKey(material, extractable),
  )
}

export async function importSecretKeyV4(
  paserk: SecretPASERK<4>,
  extractable: boolean,
): Promise<SecretKey<4>> {
  return await importPaserkKey(paserk, 4, 'secret', (material) =>
    importEd25519SecretKey(4, material, extractable),
  )
}

export async function exportSecretKey<V extends Version>(
  version: V,
  key: SecretKey<V>,
): Promise<SecretPASERK<V>> {
  const data = secretKeyData(key, version)
  requireExtractable(data)
  return serializePaserk(version, 'secret', secretMaterial(data)) as SecretPASERK<V>
}

export async function getPublicKey<V extends Version>(
  version: V,
  key: SecretKey<V>,
): Promise<PublicKey<V>> {
  const data = secretKeyData(key, version)
  return new PublicKeyImpl(version, secretPublicMaterial(data), data.publicCryptoKey)
}

export async function publicPaserkIdLegacy<V extends 1 | 3>(
  version: V,
  paserk: PublicPASERK<V>,
): Promise<PublicIdPASERK<V>> {
  validatePublicPaserkIdInput(version, paserk)
  return (await paserkIdSha384(version, 'pid', paserk)) as PublicIdPASERK<V>
}

export async function secretPaserkIdLegacy<V extends 1 | 3>(
  version: V,
  paserk: SecretIdInput<V>,
): Promise<SecretIdPASERK<V>> {
  validateSecretPaserkIdInput(version, paserk)
  return (await paserkIdSha384(version, 'sid', paserk)) as SecretIdPASERK<V>
}

function protectedSecretLength(version: 1 | 3): number | undefined {
  return version === 1 ? undefined : 48
}

export async function wrapSecretKeyLegacy<V extends 1 | 3>(
  version: V,
  key: SecretKey<V>,
  wrapping: WrappingKey<V>,
): Promise<WrappedSecretPASERK<V, 'pie'>> {
  const source = secretKeyData(key, version)
  requireExtractable(source)
  return (await wrapPieSha384(
    version,
    'secret-wrap.pie',
    secretMaterial(source),
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
  )) as WrappedSecretPASERK<V, 'pie'>
}

async function importProtectedSecretKey<V extends 1 | 3>(
  version: V,
  material: Uint8Array,
  extractable: boolean,
): Promise<SecretKey<V>> {
  if (version === 1) {
    return (await importRsaSecretKey(
      normalizeWrappedRsaSecret(material),
      extractable,
    )) as SecretKey<V>
  }
  return (await importP384SecretKey(material, extractable)) as SecretKey<V>
}

export async function unwrapSecretKeyLegacy<V extends 1 | 3>(
  version: V,
  paserk: WrappedSecretPASERK<V, 'pie'>,
  wrapping: WrappingKey<V>,
  extractable: boolean,
): Promise<SecretKey<V>> {
  const material = await unwrapPieSha384(
    version,
    'secret-wrap.pie',
    paserk,
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
    protectedSecretLength(version),
  )
  return await importProtectedSecretKey(version, material, extractable)
}

export async function wrapSecretKeyWithPasswordLegacy<V extends 1 | 3>(
  version: V,
  key: SecretKey<V>,
  password: Uint8Array,
  options: PasswordWrapOptions<V>,
): Promise<PasswordWrappedSecretPASERK<V>> {
  const source = secretKeyData(key, version)
  requireExtractable(source)
  return (await wrapPasswordSha384(
    version,
    'secret-pw',
    secretMaterial(source),
    password,
    options as PasswordWrapOptions<1 | 3>,
  )) as PasswordWrappedSecretPASERK<V>
}

export async function unwrapSecretKeyWithPasswordLegacy<V extends 1 | 3>(
  version: V,
  paserk: PasswordWrappedSecretPASERK<V>,
  password: Uint8Array,
  limits: PasswordUnwrapLimits<V>,
  extractable: boolean,
): Promise<SecretKey<V>> {
  const material = await unwrapPasswordSha384(
    version,
    'secret-pw',
    paserk,
    password,
    limits as PasswordUnwrapLimits<1 | 3>,
    protectedSecretLength(version),
  )
  return await importProtectedSecretKey(version, material, extractable)
}
