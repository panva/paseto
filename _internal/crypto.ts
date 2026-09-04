import {
  InvalidKeyError,
  InvalidTokenError,
  UnsupportedAlgorithmError,
  type CryptoKey,
  type Version,
} from '../index.ts'

import {
  PAE,
  ascii,
  b64,
  checkBytes,
  concat,
  decodeBase64url,
  empty,
  equalBytes,
  randomBytes,
  toB64u,
  webCryptoBytes,
} from './bytes.ts'
import {
  PublicKeyImpl,
  SecretKeyImpl,
  type PublicKey,
  type PublicKeyData,
  type SealingSecretKeyData,
  type SecretKey,
  type SecretKeyData,
} from './keys.ts'

function isNotSupportedError(cause: unknown): boolean {
  return (
    cause !== null &&
    typeof cause === 'object' &&
    'name' in cause &&
    cause.name === 'NotSupportedError'
  )
}

export async function webCryptoOperation<T>(
  algorithm: string,
  operation: () => Promise<T>,
): Promise<T> {
  try {
    return await operation()
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    if (isNotSupportedError(cause)) {
      throw new UnsupportedAlgorithmError(
        `${algorithm} is not available from the Web Cryptography runtime API`,
        { cause },
      )
    }
    throw cause
  }
}

export async function digest(name: 'SHA-384', input: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(
    await webCryptoOperation(name, () => crypto.subtle.digest(name, webCryptoBytes(input))),
  )
}

export async function hmacSha384(key: Uint8Array, input: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await webCryptoOperation('HMAC', () =>
    crypto.subtle.importKey('raw', webCryptoBytes(key), { name: 'HMAC', hash: 'SHA-384' }, false, [
      'sign',
    ]),
  )
  return new Uint8Array(
    await webCryptoOperation('HMAC', () =>
      crypto.subtle.sign('HMAC', cryptoKey, webCryptoBytes(input)),
    ),
  )
}

function assertCryptoKey(key: CryptoKey): void {
  if (
    key === null ||
    typeof key !== 'object' ||
    Reflect.get(key, Symbol.toStringTag) !== 'CryptoKey' ||
    key.algorithm === null ||
    typeof key.algorithm !== 'object' ||
    typeof key.algorithm.name !== 'string' ||
    typeof key.extractable !== 'boolean' ||
    typeof key.type !== 'string' ||
    !Array.isArray(key.usages)
  ) {
    throw new InvalidKeyError('Expected a CryptoKey')
  }
}

function requireKeyUsage(key: CryptoKey, usage: string): void {
  if (!key.usages.includes(usage as KeyUsage)) {
    throw new InvalidKeyError(`CryptoKey usages must include ${usage}`)
  }
}

/** Validates a CryptoKey accepted by the built-in v1.local and v3.local implementations. */
export function assertLocalCryptoKey(key: CryptoKey): void {
  assertCryptoKey(key)
  if (key.type !== 'secret' || key.algorithm.name !== 'HKDF') {
    throw new InvalidKeyError('Expected an HKDF secret CryptoKey')
  }
  requireKeyUsage(key, 'deriveBits')
}

function assertPrivateSigningCryptoKey(key: CryptoKey): void {
  assertCryptoKey(key)
  if (key.type !== 'private') throw new InvalidKeyError('Expected a private CryptoKey')
  requireKeyUsage(key, 'sign')
}

function assertPublicVerificationCryptoKey(key: CryptoKey): void {
  assertCryptoKey(key)
  if (key.type !== 'public') throw new InvalidKeyError('Expected a public CryptoKey')
  requireKeyUsage(key, 'verify')
}

function assertRsaSecretCryptoKey(key: CryptoKey): void {
  assertPrivateSigningCryptoKey(key)
  assertRsaPssKey(key, 'private')
}

function assertRsaPublicCryptoKey(key: CryptoKey): void {
  assertPublicVerificationCryptoKey(key)
  assertRsaPssKey(key, 'public')
}

function assertP384SecretCryptoKey(key: CryptoKey): void {
  assertPrivateSigningCryptoKey(key)
  const algorithm = key.algorithm as EcKeyAlgorithm
  if (algorithm.name !== 'ECDSA' || algorithm.namedCurve !== 'P-384') {
    throw new InvalidKeyError('Expected an ECDSA P-384 CryptoKey')
  }
}

function assertP384PublicCryptoKey(key: CryptoKey): void {
  assertPublicVerificationCryptoKey(key)
  const algorithm = key.algorithm as EcKeyAlgorithm
  if (algorithm.name !== 'ECDSA' || algorithm.namedCurve !== 'P-384') {
    throw new InvalidKeyError('Expected an ECDSA P-384 CryptoKey')
  }
}

function assertEd25519SecretCryptoKey(key: CryptoKey): void {
  assertPrivateSigningCryptoKey(key)
  if (key.algorithm.name !== 'Ed25519') {
    throw new InvalidKeyError('Expected an Ed25519 CryptoKey')
  }
}

function assertEd25519PublicCryptoKey(key: CryptoKey): void {
  assertPublicVerificationCryptoKey(key)
  if (key.algorithm.name !== 'Ed25519') {
    throw new InvalidKeyError('Expected an Ed25519 CryptoKey')
  }
}

/** Imports PASETO local key material as the native derivation key used by v1.local and v3.local. */
export async function importLocalCryptoKey(material: Uint8Array): Promise<CryptoKey> {
  return await webCryptoOperation('HKDF', () =>
    crypto.subtle.importKey('raw', webCryptoBytes(material), 'HKDF', false, ['deriveBits']),
  )
}

export async function hkdfSha384(
  key: Uint8Array | CryptoKey,
  info: Uint8Array,
  length: number,
  salt: Uint8Array = empty,
): Promise<Uint8Array> {
  const cryptoKey = key instanceof Uint8Array ? await importLocalCryptoKey(key) : key
  return new Uint8Array(
    await webCryptoOperation('HKDF', () =>
      crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-384', salt: webCryptoBytes(salt), info: webCryptoBytes(info) },
        cryptoKey,
        length * 8,
      ),
    ),
  )
}

export async function pbkdf2Sha384(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Promise<Uint8Array> {
  const key = await webCryptoOperation('PBKDF2', () =>
    crypto.subtle.importKey('raw', webCryptoBytes(password), 'PBKDF2', false, ['deriveBits']),
  )
  return new Uint8Array(
    await webCryptoOperation('PBKDF2', () =>
      crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-384', salt: webCryptoBytes(salt), iterations },
        key,
        length * 8,
      ),
    ),
  )
}

export async function aesCtr(
  operation: 'encrypt' | 'decrypt',
  key: Uint8Array,
  counter: Uint8Array,
  input: Uint8Array,
): Promise<Uint8Array> {
  const usages: KeyUsage[] = [operation]
  const cryptoKey = await webCryptoOperation('AES-CTR', () =>
    crypto.subtle.importKey('raw', webCryptoBytes(key), 'AES-CTR', false, usages),
  )
  return new Uint8Array(
    await webCryptoOperation('AES-CTR', () =>
      crypto.subtle[operation](
        { name: 'AES-CTR', counter: webCryptoBytes(counter), length: 128 },
        cryptoKey,
        webCryptoBytes(input),
      ),
    ),
  )
}

// ============================================================================
// P-384 and Ed25519 key encoding helpers
// ============================================================================

function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length)
  if (length < 0x100) return Uint8Array.of(0x81, length)
  return Uint8Array.of(0x82, length >>> 8, length & 0xff)
}

function der(tag: number, body: Uint8Array): Uint8Array {
  return concat(Uint8Array.of(tag), derLength(body.byteLength), body)
}

function derInteger(input: Uint8Array): Uint8Array {
  let offset = 0
  while (offset + 1 < input.byteLength && input[offset] === 0) offset++
  const value = input.subarray(offset)
  return der(0x02, (value[0]! & 0x80) === 0 ? value : concat(Uint8Array.of(0), value))
}

const rsaAlgorithmIdentifier = /* @__PURE__ */ Uint8Array.of(
  0x30,
  0x0d,
  0x06,
  0x09,
  0x2a,
  0x86,
  0x48,
  0x86,
  0xf7,
  0x0d,
  0x01,
  0x01,
  0x01,
  0x05,
  0x00,
)

function rsaPrivatePkcs8(pkcs1: Uint8Array): Uint8Array {
  return der(
    0x30,
    concat(Uint8Array.of(0x02, 0x01, 0x00), rsaAlgorithmIdentifier, der(0x04, pkcs1)),
  )
}

function rsaPrivatePkcs1(jwk: JsonWebKey): Uint8Array {
  const integer = (value: string | undefined, name: string): Uint8Array =>
    derInteger(jwkBytes(value, name))
  return der(
    0x30,
    concat(
      Uint8Array.of(0x02, 0x01, 0x00),
      integer(jwk.n, 'n'),
      integer(jwk.e, 'e'),
      integer(jwk.d, 'd'),
      integer(jwk.p, 'p'),
      integer(jwk.q, 'q'),
      integer(jwk.dp, 'dp'),
      integer(jwk.dq, 'dq'),
      integer(jwk.qi, 'qi'),
    ),
  )
}

export function pemToDer(input: string): Uint8Array {
  const normalized = input.replaceAll('\r\n', '\n').trim()
  const match =
    /^-----BEGIN RSA PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END RSA PRIVATE KEY-----$/u.exec(
      normalized,
    )
  if (match === null) throw new InvalidKeyError('Invalid RSA private key PEM')
  const body = match[1]!.replaceAll('\n', '')
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(body)) {
    throw new InvalidKeyError('Invalid RSA private key PEM')
  }
  try {
    return b64(body)
  } catch (cause) {
    throw new InvalidKeyError('Invalid RSA private key PEM', { cause })
  }
}

const p384AlgorithmIdentifier = /* @__PURE__ */ Uint8Array.of(
  0x30,
  0x10,
  0x06,
  0x07,
  0x2a,
  0x86,
  0x48,
  0xce,
  0x3d,
  0x02,
  0x01,
  0x06,
  0x05,
  0x2b,
  0x81,
  0x04,
  0x00,
  0x22,
)

const p384Order = /* @__PURE__ */ BigInt(
  '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
)
const p384Generator = {
  x: /* @__PURE__ */ BigInt(
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
  ),
  y: /* @__PURE__ */ BigInt(
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
  ),
}

export async function decompressP384(compressed: Uint8Array): Promise<Uint8Array> {
  if (compressed.byteLength !== 49 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new InvalidKeyError('Invalid P-384 public key')
  }
  try {
    const key = await p384PublicCryptoKey(compressed, 'ECDH', [], true)
    return await exportRawPublicCryptoKey(key)
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError || cause instanceof InvalidKeyError) throw cause
    throw new InvalidKeyError('Invalid P-384 public key', { cause })
  }
}

function p384PrivatePkcs8(scalar: Uint8Array, publicKey?: Uint8Array): Uint8Array {
  const fields = [Uint8Array.of(0x02, 0x01, 0x01), der(0x04, scalar)]
  if (publicKey !== undefined) {
    if (publicKey.byteLength !== 97 || publicKey[0] !== 0x04) {
      throw new InvalidKeyError('Invalid P-384 public key')
    }
    fields.push(der(0xa1, der(0x03, concat(Uint8Array.of(0), publicKey))))
  }
  const ecPrivate = der(0x30, concat(...fields))
  return der(
    0x30,
    concat(Uint8Array.of(0x02, 0x01, 0x00), p384AlgorithmIdentifier, der(0x04, ecPrivate)),
  )
}

function p384PublicSpki(compressed: Uint8Array): Uint8Array {
  return der(0x30, concat(p384AlgorithmIdentifier, der(0x03, concat(Uint8Array.of(0), compressed))))
}

export function compressP384(raw: Uint8Array): Uint8Array {
  if (raw.byteLength !== 97 || raw[0] !== 0x04)
    throw new InvalidKeyError('Invalid P-384 public key')
  return concat(Uint8Array.of(0x02 | (raw[96]! & 1)), raw.subarray(1, 49))
}

function ed25519PrivatePkcs8(seed: Uint8Array): Uint8Array {
  return concat(
    Uint8Array.of(
      0x30,
      0x2e,
      0x02,
      0x01,
      0x00,
      0x30,
      0x05,
      0x06,
      0x03,
      0x2b,
      0x65,
      0x70,
      0x04,
      0x22,
      0x04,
      0x20,
    ),
    seed,
  )
}

export function jwkBytes(value: string | undefined, name: string): Uint8Array {
  if (value === undefined) throw new InvalidKeyError(`Missing ${name} in exported key`)
  return decodeBase64url(value, name)
}

function assertRsaPssKey(key: CryptoKey, type: 'public' | 'private'): void {
  if (key.type !== type) throw new InvalidKeyError(`Expected an RSA-PSS ${type} key`)
  const algorithm = key.algorithm as RsaHashedKeyAlgorithm
  if (
    algorithm.name !== 'RSA-PSS' ||
    algorithm.hash?.name !== 'SHA-384' ||
    algorithm.modulusLength !== 2048 ||
    algorithm.publicExponent === undefined ||
    !equalBytes(new Uint8Array(algorithm.publicExponent), Uint8Array.of(0x01, 0x00, 0x01))
  ) {
    throw new InvalidKeyError('v1.public requires a 2048-bit RSA key with exponent 65537')
  }
}

async function importRsaPssPublicKey(
  material: Uint8Array,
  extractable: boolean = false,
): Promise<CryptoKey> {
  const key = await webCryptoOperation('RSA-PSS', () =>
    crypto.subtle.importKey(
      'spki',
      webCryptoBytes(material),
      { name: 'RSA-PSS', hash: 'SHA-384' },
      extractable,
      ['verify'],
    ),
  )
  assertRsaPssKey(key, 'public')
  return key
}

async function importRsaPssPrivateKey(
  material: Uint8Array,
  extractable: boolean = false,
): Promise<CryptoKey> {
  const key = await webCryptoOperation('RSA-PSS', () =>
    crypto.subtle.importKey(
      'pkcs8',
      webCryptoBytes(rsaPrivatePkcs8(material)),
      { name: 'RSA-PSS', hash: 'SHA-384' },
      extractable,
      ['sign'],
    ),
  )
  assertRsaPssKey(key, 'private')
  return key
}

async function generateRsaPssKeyPair(extractable: boolean): Promise<CryptoKeyPair> {
  return await webCryptoOperation(
    'RSA-PSS',
    () =>
      crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
          hash: 'SHA-384',
        },
        extractable,
        ['sign', 'verify'],
      ) as Promise<CryptoKeyPair>,
  )
}

async function exportRsaPssPrivatePkcs1(key: CryptoKey): Promise<Uint8Array> {
  assertRsaPssKey(key, 'private')
  return rsaPrivatePkcs1(
    await webCryptoOperation('RSA-PSS', () => crypto.subtle.exportKey('jwk', key)),
  )
}

async function exportRsaPssPublicSpki(key: CryptoKey): Promise<Uint8Array> {
  assertRsaPssKey(key, 'public')
  return new Uint8Array(
    await webCryptoOperation('RSA-PSS', () => crypto.subtle.exportKey('spki', key)),
  )
}

type PublicJwk = (jwk: JsonWebKey) => JsonWebKey

function rsaPublicJwk(jwk: JsonWebKey): JsonWebKey {
  return { kty: jwk.kty, n: jwk.n, e: jwk.e, ext: true, key_ops: ['verify'] } as JsonWebKey
}

function curvePublicJwk(jwk: JsonWebKey): JsonWebKey {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    ext: true,
    key_ops: ['verify'],
  } as JsonWebKey
}

async function getPublicKeyByExport(key: CryptoKey, toPublicJwk: PublicJwk): Promise<CryptoKey> {
  if (!key.extractable) {
    throw new UnsupportedAlgorithmError(
      'SubtleCrypto.getPublicKey is required for a non-extractable private CryptoKey',
    )
  }

  const jwk = await webCryptoOperation(key.algorithm.name, () =>
    crypto.subtle.exportKey('jwk', key),
  )
  return await webCryptoOperation(key.algorithm.name, () =>
    crypto.subtle.importKey('jwk', toPublicJwk(jwk), key.algorithm, true, ['verify']),
  )
}

async function getPublicCryptoKey(key: CryptoKey, toPublicJwk: PublicJwk): Promise<CryptoKey> {
  const publicKey = (await webCryptoOperation(key.algorithm.name, () =>
    // @ts-expect-error SubtleCrypto.getPublicKey is not declared by every TypeScript Web Crypto lib.
    crypto.subtle.getPublicKey?.(key, ['verify']),
  )) as CryptoKey | undefined
  return publicKey ?? (await getPublicKeyByExport(key, toPublicJwk))
}

async function exportRawPublicCryptoKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(
    await webCryptoOperation(key.algorithm.name, () => crypto.subtle.exportKey('raw', key)),
  )
}

/** Wraps a native RSA-PSS public key for use with the built-in v1.public implementation. */
export async function importRsaPublicCryptoKey(key: CryptoKey): Promise<PublicKey<1>> {
  assertRsaPublicCryptoKey(key)
  const material = key.extractable ? await exportRsaPssPublicSpki(key) : undefined
  return new PublicKeyImpl(1, material, key)
}

/** Wraps a native Ed25519 public key for a built-in public-purpose implementation. */
export async function importEd25519PublicCryptoKey<V extends 2 | 4>(
  version: V,
  key: CryptoKey,
): Promise<PublicKey<V>> {
  assertEd25519PublicCryptoKey(key)
  const material = key.extractable ? await exportRawPublicCryptoKey(key) : undefined
  return new PublicKeyImpl(version, material, key)
}

/** Wraps a native ECDSA P-384 public key for the built-in v3.public implementation. */
export async function importP384PublicCryptoKey(key: CryptoKey): Promise<PublicKey<3>> {
  assertP384PublicCryptoKey(key)
  if (!key.extractable) {
    throw new InvalidKeyError('v3.public requires an extractable public CryptoKey')
  }
  const material = compressP384(await exportRawPublicCryptoKey(key))
  return new PublicKeyImpl(3, material, key)
}

/** Wraps a native RSA-PSS private key for use with the built-in v1.public implementation. */
export async function importRsaSecretCryptoKey(key: CryptoKey): Promise<SecretKey<1>> {
  assertRsaSecretCryptoKey(key)
  const publicKey = await getPublicCryptoKey(key, rsaPublicJwk)
  const publicMaterial = await exportRsaPssPublicSpki(publicKey)
  const material = key.extractable ? await exportRsaPssPrivatePkcs1(key) : undefined
  return new SecretKeyImpl(1, key, material, publicMaterial, undefined, publicKey)
}

/** Wraps a native Ed25519 private key for a built-in public-purpose implementation. */
export async function importEd25519SecretCryptoKey<V extends 2 | 4>(
  version: V,
  key: CryptoKey,
): Promise<SecretKey<V>> {
  assertEd25519SecretCryptoKey(key)
  const publicKey = await getPublicCryptoKey(key, curvePublicJwk)
  const publicMaterial = await exportRawPublicCryptoKey(publicKey)
  const material = key.extractable
    ? concat(
        jwkBytes(
          (await webCryptoOperation('Ed25519', () => crypto.subtle.exportKey('jwk', key))).d,
          'd',
        ),
        publicMaterial,
      )
    : undefined
  return new SecretKeyImpl(version, key, material, publicMaterial, undefined, publicKey)
}

/** Wraps a native ECDSA P-384 private key for the built-in v3.public implementation. */
export async function importP384SecretCryptoKey(key: CryptoKey): Promise<SecretKey<3>> {
  assertP384SecretCryptoKey(key)
  const publicKey = await getPublicCryptoKey(key, curvePublicJwk)
  const rawPublicMaterial = await exportRawPublicCryptoKey(publicKey)
  const material = key.extractable
    ? jwkBytes(
        (await webCryptoOperation('ECDSA with P-384', () => crypto.subtle.exportKey('jwk', key))).d,
        'd',
      )
    : undefined
  return new SecretKeyImpl(
    3,
    key,
    material,
    compressP384(rawPublicMaterial),
    rawPublicMaterial,
    publicKey,
  )
}

export async function importRsaSecretKey(
  material: Uint8Array,
  extractable: boolean,
): Promise<SecretKey<1>> {
  checkBytes(material, 'material')
  try {
    const privateKey = await importRsaPssPrivateKey(material, true)
    const canonicalPrivate = await exportRsaPssPrivatePkcs1(privateKey)
    if (!equalBytes(material, canonicalPrivate)) {
      throw new InvalidKeyError('v1 RSA secret key is not canonical PKCS#1 DER')
    }
    const privateJwk = await webCryptoOperation('RSA-PSS', () =>
      crypto.subtle.exportKey('jwk', privateKey),
    )
    if (privateJwk.n === undefined || privateJwk.e === undefined) {
      throw new InvalidKeyError('Missing RSA public parameters in exported key')
    }
    const publicJwk: JsonWebKey = {
      kty: 'RSA',
      n: privateJwk.n,
      e: privateJwk.e,
      alg: 'PS384',
      ext: true,
      key_ops: ['verify'],
    }
    const publicKey = await webCryptoOperation('RSA-PSS', () =>
      crypto.subtle.importKey('jwk', publicJwk, { name: 'RSA-PSS', hash: 'SHA-384' }, true, [
        'verify',
      ]),
    )
    const publicMaterial = new Uint8Array(
      await webCryptoOperation('RSA-PSS', () => crypto.subtle.exportKey('spki', publicKey)),
    )
    const retained = extractable ? privateKey : await importRsaPssPrivateKey(material, false)
    return new SecretKeyImpl(
      1,
      retained,
      extractable ? canonicalPrivate : undefined,
      publicMaterial,
      undefined,
      publicKey,
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Invalid v1 RSA secret key', { cause })
  }
}

export async function generateRsaKeyPair(
  extractable: boolean,
): Promise<{ secretKey: SecretKey<1>; publicKey: PublicKey<1> }> {
  try {
    const generated = await generateRsaPssKeyPair(extractable)
    const secretMaterial = extractable
      ? await exportRsaPssPrivatePkcs1(generated.privateKey)
      : undefined
    const publicMaterial = await exportRsaPssPublicSpki(generated.publicKey)
    return {
      secretKey: new SecretKeyImpl(
        1,
        generated.privateKey,
        secretMaterial,
        publicMaterial,
        undefined,
        generated.publicKey,
      ),
      publicKey: new PublicKeyImpl(1, publicMaterial, generated.publicKey),
    }
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Unable to generate a v1 RSA key pair', { cause })
  }
}

async function importP384KeyPair(
  material: Uint8Array,
  algorithm: 'ECDSA' | 'ECDH',
  usage: 'sign' | 'deriveBits',
  extractable: boolean,
): Promise<CryptoKeyPair> {
  checkBytes(material, 'material', 48)
  const scalar = bytesToBigInt(material)
  if (scalar === 0n || scalar >= p384Order) {
    throw new InvalidKeyError('Invalid P-384 secret scalar')
  }
  // Snapshot the scalar before awaiting, including when material is a Buffer.
  const pkcs8 = p384PrivatePkcs8(material)
  const d = toB64u(material)
  const keyAlgorithm = { name: algorithm, namedCurve: 'P-384' }
  const publicUsages: KeyUsage[] = algorithm === 'ECDSA' ? ['verify'] : []
  return await webCryptoOperation(`${algorithm} with P-384`, async () => {
    const c = crypto.subtle
    async function fromJwk(jwk: JsonWebKey, privateKey?: CryptoKey): Promise<CryptoKeyPair> {
      privateKey ??= await c.importKey('jwk', jwk, keyAlgorithm, extractable, [usage])
      delete jwk.d
      const publicKey = await c.importKey('jwk', jwk, keyAlgorithm, true, publicUsages)
      return { privateKey, publicKey }
    }

    let privateKey: CryptoKey | undefined
    // @ts-expect-error SubtleCrypto.getPublicKey is not declared by every TypeScript Web Crypto lib.
    const nativePublicKey = typeof c.getPublicKey === 'function'
    try {
      privateKey = await c.importKey(
        'pkcs8',
        webCryptoBytes(pkcs8),
        keyAlgorithm,
        nativePublicKey ? extractable : true,
        [usage],
      )
      if (nativePublicKey) {
        // Also confirm that scalar-only import recovered a usable public point.
        // @ts-expect-error SubtleCrypto.getPublicKey is not declared by every TypeScript Web Crypto lib.
        const publicKey = await c.getPublicKey(privateKey, publicUsages)
        return { privateKey, publicKey }
      }
      const { x, y } = await c.exportKey('jwk', privateKey)
      return fromJwk(
        { kty: 'EC', crv: 'P-384', x: x!, y: y!, d },
        extractable ? privateKey : undefined,
      )
    } catch (cause) {
      // WebKit requires public coordinates on import; Firefox cannot export them
      // from scalar-only PKCS8. Other errors must not trigger recovery.
      // https://bugs.webkit.org/show_bug.cgi?id=302707
      // https://bugzilla.mozilla.org/show_bug.cgi?id=2000795
      if (
        !(cause instanceof DOMException) ||
        (cause.name !== 'DataError' && cause.name !== 'OperationError')
      )
        throw cause
    }

    const generator: JsonWebKey = {
      kty: 'EC',
      crv: 'P-384',
      x: toB64u(bigIntToBytes(p384Generator.x, 48)),
      y: toB64u(bigIntToBytes(p384Generator.y, 48)),
    }
    const jwk = { ...generator, d }
    const signingAlgorithm = { name: 'ECDSA', namedCurve: 'P-384' }
    const agreementAlgorithm = { name: 'ECDH', namedCurve: 'P-384' }
    async function temporaryKey(name: 'ECDSA' | 'ECDH', keyUsage: KeyUsage): Promise<CryptoKey> {
      if (privateKey?.algorithm.name === name) return privateKey
      return privateKey
        ? await c.importKey('pkcs8', webCryptoBytes(pkcs8), { name, namedCurve: 'P-384' }, false, [
            keyUsage,
          ])
        : await c.importKey('jwk', jwk, { name, namedCurve: 'P-384' }, false, [keyUsage])
    }
    const signingKey = await temporaryKey('ECDSA', 'sign')
    const agreementKey = await temporaryKey('ECDH', 'deriveBits')
    const generatorKey = await c.importKey('jwk', generator, agreementAlgorithm, true, [])
    // ECDH(d, G) recovers x(dG). Temporary keys may carry generator coordinates
    // on WebKit, so none of these private keys may escape this function.
    const x = new Uint8Array(
      await c.deriveBits({ name: 'ECDH', public: generatorKey }, agreementKey, 384),
    )
    const message = webCryptoBytes(ascii('PASETO public key recovery'))
    const signatureAlgorithm = { name: 'ECDSA', hash: 'SHA-384' }
    const signature = await c.sign(signatureAlgorithm, signingKey, message)
    // Compressed point import recovers both possible y values; verification
    // selects the public point matching the private scalar.
    for (const prefix of [0x02, 0x03]) {
      const candidate = await c.importKey(
        'spki',
        webCryptoBytes(p384PublicSpki(concat(Uint8Array.of(prefix), x))),
        signingAlgorithm,
        true,
        ['verify'],
      )
      if (await c.verify(signatureAlgorithm, candidate, signature, message)) {
        const { x, y } = await c.exportKey('jwk', candidate)
        return fromJwk({ kty: 'EC', crv: 'P-384', x: x!, y: y!, d })
      }
    }
    throw new InvalidKeyError('P-384 public key recovery failed')
  })
}

export async function p384RawPublicFromSecret(
  material: Uint8Array,
  algorithm: 'ECDSA' | 'ECDH',
  usage: 'sign' | 'deriveBits',
): Promise<Uint8Array> {
  const { publicKey } = await importP384KeyPair(material, algorithm, usage, false)
  return await exportRawPublicCryptoKey(publicKey)
}

export async function importP384SecretKey(
  material: Uint8Array,
  extractable: boolean,
): Promise<SecretKey<3>> {
  checkBytes(material, 'material', 48)
  material = new Uint8Array(material)
  const { privateKey, publicKey } = await importP384KeyPair(material, 'ECDSA', 'sign', extractable)
  const raw = await exportRawPublicCryptoKey(publicKey)
  return new SecretKeyImpl(
    3,
    privateKey,
    extractable ? material : undefined,
    compressP384(raw),
    raw,
    publicKey,
  )
}

async function importEd25519PrivateKey(seed: Uint8Array, extractable: boolean): Promise<CryptoKey> {
  return await webCryptoOperation('Ed25519', () =>
    crypto.subtle.importKey(
      'pkcs8',
      webCryptoBytes(ed25519PrivatePkcs8(seed)),
      'Ed25519',
      extractable,
      ['sign'],
    ),
  )
}

export async function importEd25519SecretKey<V extends 2 | 4>(
  version: V,
  material: Uint8Array,
  extractable: boolean,
): Promise<SecretKey<V>> {
  checkBytes(material, 'material', 64)
  const seed = material.subarray(0, 32)
  let key: CryptoKey
  try {
    key = await importEd25519PrivateKey(seed, true)
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Invalid Ed25519 secret key', { cause })
  }
  const jwk = await webCryptoOperation('Ed25519', () => crypto.subtle.exportKey('jwk', key))
  const publicMaterial = jwkBytes(jwk.x, 'x')
  if (!equalBytes(publicMaterial, material.subarray(32))) {
    throw new InvalidKeyError('Ed25519 secret key does not contain its matching public key')
  }
  const retained = extractable ? key : await importEd25519PrivateKey(seed, false)
  const publicKey = await ed25519PublicCryptoKey(publicMaterial, true)
  return new SecretKeyImpl(
    version,
    retained,
    extractable ? material : undefined,
    publicMaterial,
    undefined,
    publicKey,
  )
}

export async function generateP384KeyPair(
  extractable: boolean,
): Promise<{ secretKey: SecretKey<3>; publicKey: PublicKey<3> }> {
  const generated = await webCryptoOperation(
    'ECDSA with P-384',
    () =>
      crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, extractable, [
        'sign',
        'verify',
      ]) as Promise<CryptoKeyPair>,
  )
  const privateJwk = extractable
    ? await webCryptoOperation('ECDSA with P-384', () =>
        crypto.subtle.exportKey('jwk', generated.privateKey),
      )
    : undefined
  const publicRaw = new Uint8Array(
    await webCryptoOperation('ECDSA with P-384', () =>
      crypto.subtle.exportKey('raw', generated.publicKey),
    ),
  )
  const publicMaterial = compressP384(publicRaw)
  return {
    secretKey: new SecretKeyImpl(
      3,
      generated.privateKey,
      privateJwk === undefined ? undefined : jwkBytes(privateJwk.d, 'd'),
      publicMaterial,
      publicRaw,
      generated.publicKey,
    ),
    publicKey: new PublicKeyImpl(3, publicMaterial, generated.publicKey),
  }
}

export async function generateEd25519KeyPair<V extends 2 | 4>(
  version: V,
  extractable: boolean,
): Promise<{ secretKey: SecretKey<V>; publicKey: PublicKey<V> }> {
  const generated = await webCryptoOperation(
    'Ed25519',
    () =>
      crypto.subtle.generateKey('Ed25519', extractable, [
        'sign',
        'verify',
      ]) as Promise<CryptoKeyPair>,
  )
  const privateJwk = extractable
    ? await webCryptoOperation('Ed25519', () =>
        crypto.subtle.exportKey('jwk', generated.privateKey),
      )
    : undefined
  const publicRaw = new Uint8Array(
    await webCryptoOperation('Ed25519', () => crypto.subtle.exportKey('raw', generated.publicKey)),
  )
  const privateMaterial =
    privateJwk === undefined ? undefined : concat(jwkBytes(privateJwk.d, 'd'), publicRaw)
  return {
    secretKey: new SecretKeyImpl(
      version,
      generated.privateKey,
      privateMaterial,
      publicRaw,
      undefined,
      generated.publicKey,
    ),
    publicKey: new PublicKeyImpl(version, publicRaw, generated.publicKey),
  }
}

export async function importRsaPublicKey(material: Uint8Array): Promise<PublicKey<1>> {
  checkBytes(material, 'material')
  let cryptoKey: CryptoKey
  try {
    cryptoKey = await importRsaPssPublicKey(material, true)
    const algorithm = cryptoKey.algorithm as RsaHashedKeyAlgorithm
    if (
      algorithm.modulusLength !== 2048 ||
      !equalBytes(new Uint8Array(algorithm.publicExponent), Uint8Array.of(0x01, 0x00, 0x01))
    ) {
      throw new InvalidKeyError('v1.public requires a 2048-bit RSA key with exponent 65537')
    }
    const canonical = await exportRsaPssPublicSpki(cryptoKey)
    if (!equalBytes(material, canonical)) {
      throw new InvalidKeyError('v1 RSA public key is not canonical SPKI DER')
    }
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    if (cause instanceof InvalidKeyError) throw cause
    throw new InvalidKeyError('Invalid v1 public key', { cause })
  }
  return new PublicKeyImpl(1, material, cryptoKey)
}

export async function p384PublicCryptoKey(
  material: Uint8Array,
  algorithm: 'ECDSA' | 'ECDH',
  usages: KeyUsage[],
  extractable: boolean = false,
): Promise<CryptoKey> {
  try {
    return await webCryptoOperation(`${algorithm} with P-384`, () =>
      crypto.subtle.importKey(
        'spki',
        webCryptoBytes(p384PublicSpki(material)),
        { name: algorithm, namedCurve: 'P-384' },
        extractable,
        usages,
      ),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Invalid P-384 public key', { cause })
  }
}

export async function p384PrivateCryptoKey(
  data: SecretKeyData<3> | SealingSecretKeyData<3>,
  algorithm: 'ECDSA' | 'ECDH',
  usage: 'sign' | 'deriveBits',
): Promise<CryptoKey> {
  if ('cryptoKey' in data) return data.cryptoKey
  const publicMaterial = data.publicMaterial
  try {
    const pkcs8 = p384PrivatePkcs8(data.material, await decompressP384(publicMaterial))
    return await webCryptoOperation(`${algorithm} with P-384`, () =>
      crypto.subtle.importKey(
        'pkcs8',
        webCryptoBytes(pkcs8),
        { name: algorithm, namedCurve: 'P-384' },
        false,
        [usage],
      ),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Invalid P-384 secret key', { cause })
  }
}

export async function importP384PublicKey(material: Uint8Array): Promise<PublicKey<3>> {
  checkBytes(material, 'material', 49)
  const cryptoKey = await p384PublicCryptoKey(material, 'ECDSA', ['verify'], true)
  return new PublicKeyImpl(3, material, cryptoKey)
}

export async function importEd25519PublicKey<V extends 2 | 4>(
  version: V,
  material: Uint8Array,
): Promise<PublicKey<V>> {
  checkBytes(material, 'material', 32)
  let cryptoKey: CryptoKey
  try {
    cryptoKey = await webCryptoOperation('Ed25519', () =>
      crypto.subtle.importKey('raw', webCryptoBytes(material), 'Ed25519', true, ['verify']),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError(`Invalid v${version} public key`, { cause })
  }
  return new PublicKeyImpl(version, material, cryptoKey)
}

async function ed25519PublicCryptoKey(
  material: Uint8Array,
  extractable: boolean = false,
): Promise<CryptoKey> {
  try {
    return await webCryptoOperation('Ed25519', () =>
      crypto.subtle.importKey('raw', webCryptoBytes(material), 'Ed25519', extractable, ['verify']),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Invalid Ed25519 public key', { cause })
  }
}

function tokenHeader(version: Version, purpose: 'local' | 'public'): Uint8Array {
  return ascii(`v${version}.${purpose}.`)
}

export async function encryptV1Local(
  key: Uint8Array | CryptoKey,
  message: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  const header = tokenHeader(1, 'local')
  const nonce = (await hmacSha384(randomBytes(32), message)).subarray(0, 32)
  const encryptionKey = await hkdfSha384(
    key,
    ascii('paseto-encryption-key'),
    32,
    nonce.subarray(0, 16),
  )
  const authenticationKey = await hkdfSha384(
    key,
    ascii('paseto-auth-key-for-aead'),
    32,
    nonce.subarray(0, 16),
  )
  const ciphertext = await aesCtr('encrypt', encryptionKey, nonce.subarray(16), message)
  const tag = await hmacSha384(authenticationKey, PAE([header, nonce, ciphertext, footer]))
  return concat(nonce, ciphertext, tag)
}

export async function encryptV3Local(
  key: Uint8Array | CryptoKey,
  message: Uint8Array,
  footer: Uint8Array,
  implicit: Uint8Array,
): Promise<Uint8Array> {
  const header = tokenHeader(3, 'local')
  const nonce = randomBytes(32)
  const temporary = await hkdfSha384(key, concat(ascii('paseto-encryption-key'), nonce), 48)
  const authenticationKey = await hkdfSha384(
    key,
    concat(ascii('paseto-auth-key-for-aead'), nonce),
    48,
  )
  const ciphertext = await aesCtr(
    'encrypt',
    temporary.subarray(0, 32),
    temporary.subarray(32),
    message,
  )
  const tag = await hmacSha384(
    authenticationKey,
    PAE([header, nonce, ciphertext, footer, implicit]),
  )
  return concat(nonce, ciphertext, tag)
}

export async function decryptV1Local(
  key: Uint8Array | CryptoKey,
  payload: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  const header = tokenHeader(1, 'local')
  if (payload.byteLength < 80) throw new InvalidTokenError('Truncated v1.local payload')
  const nonce = payload.subarray(0, 32)
  const ciphertext = payload.subarray(32, -48)
  const tag = payload.subarray(-48)
  const encryptionKey = await hkdfSha384(
    key,
    ascii('paseto-encryption-key'),
    32,
    nonce.subarray(0, 16),
  )
  const authenticationKey = await hkdfSha384(
    key,
    ascii('paseto-auth-key-for-aead'),
    32,
    nonce.subarray(0, 16),
  )
  const expected = await hmacSha384(authenticationKey, PAE([header, nonce, ciphertext, footer]))
  if (!equalBytes(tag, expected)) throw new InvalidTokenError('Token authentication failed')
  return await aesCtr('decrypt', encryptionKey, nonce.subarray(16), ciphertext)
}

export async function decryptV3Local(
  key: Uint8Array | CryptoKey,
  payload: Uint8Array,
  footer: Uint8Array,
  implicit: Uint8Array,
): Promise<Uint8Array> {
  const header = tokenHeader(3, 'local')
  if (payload.byteLength < 80) throw new InvalidTokenError('Truncated v3.local payload')
  const nonce = payload.subarray(0, 32)
  const ciphertext = payload.subarray(32, -48)
  const tag = payload.subarray(-48)
  const temporary = await hkdfSha384(key, concat(ascii('paseto-encryption-key'), nonce), 48)
  const authenticationKey = await hkdfSha384(
    key,
    concat(ascii('paseto-auth-key-for-aead'), nonce),
    48,
  )
  const expected = await hmacSha384(
    authenticationKey,
    PAE([header, nonce, ciphertext, footer, implicit]),
  )
  if (!equalBytes(tag, expected)) throw new InvalidTokenError('Token authentication failed')
  return await aesCtr('decrypt', temporary.subarray(0, 32), temporary.subarray(32), ciphertext)
}

function bytesToBigInt(input: Uint8Array): bigint {
  let value = 0n
  for (const byte of input) value = (value << 8n) | BigInt(byte)
  return value
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new RangeError('value must not be negative')
  const output = new Uint8Array(length)
  let remainder = value
  for (let i = length - 1; i >= 0; i--) {
    output[i] = Number(remainder & 0xffn)
    remainder >>= 8n
  }
  if (remainder !== 0n) throw new RangeError('value does not fit')
  return output
}

function normalizeP384Signature(signature: Uint8Array): Uint8Array {
  if (signature.byteLength !== 96) throw new InvalidTokenError('Invalid P-384 signature length')
  const s = bytesToBigInt(signature.subarray(48))
  if (s <= p384Order / 2n) return signature
  return concat(signature.subarray(0, 48), bigIntToBytes(p384Order - s, 48))
}

function publicMaterial(data: PublicKeyData<Version>): Uint8Array {
  if (data.material === undefined) throw new InvalidKeyError('Public key material is not available')
  return data.material
}

export async function signV1Public(
  data: SecretKeyData<1>,
  message: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  const key = data.cryptoKey
  return new Uint8Array(
    await webCryptoOperation('RSA-PSS', () =>
      crypto.subtle.sign(
        { name: 'RSA-PSS', saltLength: 48 },
        key,
        webCryptoBytes(PAE([tokenHeader(1, 'public'), message, footer])),
      ),
    ),
  )
}

export async function verifyV1Public(
  data: PublicKeyData<1>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
): Promise<boolean> {
  const key = data.cryptoKey
  try {
    return await webCryptoOperation('RSA-PSS', () =>
      crypto.subtle.verify(
        { name: 'RSA-PSS', saltLength: 48 },
        key,
        webCryptoBytes(signature),
        webCryptoBytes(PAE([tokenHeader(1, 'public'), message, footer])),
      ),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidTokenError('Token signature verification failed', { cause })
  }
}

export async function signV3Public(
  data: SecretKeyData<3>,
  message: Uint8Array,
  footer: Uint8Array,
  implicit: Uint8Array,
): Promise<Uint8Array> {
  const key = data.cryptoKey
  const publicMaterial = data.publicMaterial
  if (publicMaterial === undefined) throw new InvalidKeyError('Missing P-384 public key material')
  return normalizeP384Signature(
    new Uint8Array(
      await webCryptoOperation('ECDSA with P-384', () =>
        crypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-384' },
          key,
          webCryptoBytes(
            PAE([publicMaterial, tokenHeader(3, 'public'), message, footer, implicit]),
          ),
        ),
      ),
    ),
  )
}

export async function verifyV3Public(
  data: PublicKeyData<3>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
  implicit: Uint8Array,
): Promise<boolean> {
  const material = publicMaterial(data)
  const key = data.cryptoKey
  try {
    return await webCryptoOperation('ECDSA with P-384', () =>
      crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-384' },
        key,
        webCryptoBytes(signature),
        webCryptoBytes(PAE([material, tokenHeader(3, 'public'), message, footer, implicit])),
      ),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidTokenError('Token signature verification failed', { cause })
  }
}

async function signEd25519Public(
  data: SecretKeyData<2 | 4>,
  pieces: Uint8Array[],
): Promise<Uint8Array> {
  const key = data.cryptoKey
  return new Uint8Array(
    await webCryptoOperation('Ed25519', () =>
      crypto.subtle.sign('Ed25519', key, webCryptoBytes(PAE(pieces))),
    ),
  )
}

async function verifyEd25519Public(
  data: PublicKeyData<2 | 4>,
  signature: Uint8Array,
  pieces: Uint8Array[],
): Promise<boolean> {
  const key = data.cryptoKey
  try {
    return await webCryptoOperation('Ed25519', () =>
      crypto.subtle.verify('Ed25519', key, webCryptoBytes(signature), webCryptoBytes(PAE(pieces))),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidTokenError('Token signature verification failed', { cause })
  }
}

export async function signV2Public(
  data: SecretKeyData<2>,
  message: Uint8Array,
  footer: Uint8Array,
): Promise<Uint8Array> {
  return await signEd25519Public(data, [tokenHeader(2, 'public'), message, footer])
}

export async function verifyV2Public(
  data: PublicKeyData<2>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
): Promise<boolean> {
  return await verifyEd25519Public(data, signature, [tokenHeader(2, 'public'), message, footer])
}

export async function signV4Public(
  data: SecretKeyData<4>,
  message: Uint8Array,
  footer: Uint8Array,
  implicit: Uint8Array,
): Promise<Uint8Array> {
  return await signEd25519Public(data, [tokenHeader(4, 'public'), message, footer, implicit])
}

export async function verifyV4Public(
  data: PublicKeyData<4>,
  message: Uint8Array,
  signature: Uint8Array,
  footer: Uint8Array,
  implicit: Uint8Array,
): Promise<boolean> {
  return await verifyEd25519Public(data, signature, [
    tokenHeader(4, 'public'),
    message,
    footer,
    implicit,
  ])
}
