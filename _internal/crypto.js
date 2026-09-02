import {
  InvalidKeyError,
  InvalidTokenError,
  UnsupportedAlgorithmError,


} from '../index.js'

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
  webCryptoBytes,
} from './bytes.js'
import {
  PublicKeyImpl,
  SecretKeyImpl,





} from './keys.js'

function isNotSupportedError(cause         )          {
  return (
    cause !== null &&
    typeof cause === 'object' &&
    'name' in cause &&
    cause.name === 'NotSupportedError'
  )
}

export async function webCryptoOperation   (
  algorithm        ,
  operation                  ,
)             {
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

export async function digest(name           , input            )                      {
  return new Uint8Array(
    await webCryptoOperation(name, () => crypto.subtle.digest(name, webCryptoBytes(input))),
  )
}

export async function hmacSha384(key            , input            )                      {
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

function assertCryptoKey(key           )       {
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

function requireKeyUsage(key           , usage        )       {
  if (!key.usages.includes(usage            )) {
    throw new InvalidKeyError(`CryptoKey usages must include ${usage}`)
  }
}


export function assertLocalCryptoKey(key           )       {
  assertCryptoKey(key)
  if (key.type !== 'secret' || key.algorithm.name !== 'HKDF') {
    throw new InvalidKeyError('Expected an HKDF secret CryptoKey')
  }
  requireKeyUsage(key, 'deriveBits')
}

function assertPrivateSigningCryptoKey(key           )       {
  assertCryptoKey(key)
  if (key.type !== 'private') throw new InvalidKeyError('Expected a private CryptoKey')
  requireKeyUsage(key, 'sign')
}

function assertPublicVerificationCryptoKey(key           )       {
  assertCryptoKey(key)
  if (key.type !== 'public') throw new InvalidKeyError('Expected a public CryptoKey')
  requireKeyUsage(key, 'verify')
}

function assertRsaSecretCryptoKey(key           )       {
  assertPrivateSigningCryptoKey(key)
  assertRsaPssKey(key, 'private')
}

function assertRsaPublicCryptoKey(key           )       {
  assertPublicVerificationCryptoKey(key)
  assertRsaPssKey(key, 'public')
}

function assertP384SecretCryptoKey(key           )       {
  assertPrivateSigningCryptoKey(key)
  const algorithm = key.algorithm                  
  if (algorithm.name !== 'ECDSA' || algorithm.namedCurve !== 'P-384') {
    throw new InvalidKeyError('Expected an ECDSA P-384 CryptoKey')
  }
}

function assertP384PublicCryptoKey(key           )       {
  assertPublicVerificationCryptoKey(key)
  const algorithm = key.algorithm                  
  if (algorithm.name !== 'ECDSA' || algorithm.namedCurve !== 'P-384') {
    throw new InvalidKeyError('Expected an ECDSA P-384 CryptoKey')
  }
}

function assertEd25519SecretCryptoKey(key           )       {
  assertPrivateSigningCryptoKey(key)
  if (key.algorithm.name !== 'Ed25519') {
    throw new InvalidKeyError('Expected an Ed25519 CryptoKey')
  }
}

function assertEd25519PublicCryptoKey(key           )       {
  assertPublicVerificationCryptoKey(key)
  if (key.algorithm.name !== 'Ed25519') {
    throw new InvalidKeyError('Expected an Ed25519 CryptoKey')
  }
}


export async function importLocalCryptoKey(material            )                     {
  return await webCryptoOperation('HKDF', () =>
    crypto.subtle.importKey('raw', webCryptoBytes(material), 'HKDF', false, ['deriveBits']),
  )
}

export async function hkdfSha384(
  key                        ,
  info            ,
  length        ,
  salt             = empty,
)                      {
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
  password            ,
  salt            ,
  iterations        ,
  length        ,
)                      {
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
  operation                       ,
  key            ,
  counter            ,
  input            ,
)                      {
  const usages             = [operation]
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





function derLength(length        )             {
  if (length < 0x80) return Uint8Array.of(length)
  if (length < 0x100) return Uint8Array.of(0x81, length)
  return Uint8Array.of(0x82, length >>> 8, length & 0xff)
}

function der(tag        , body            )             {
  return concat(Uint8Array.of(tag), derLength(body.byteLength), body)
}

function derInteger(input            )             {
  let offset = 0
  while (offset + 1 < input.byteLength && input[offset] === 0) offset++
  const value = input.subarray(offset)
  return der(0x02, (value[0]  & 0x80) === 0 ? value : concat(Uint8Array.of(0), value))
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

function rsaPrivatePkcs8(pkcs1            )             {
  return der(
    0x30,
    concat(Uint8Array.of(0x02, 0x01, 0x00), rsaAlgorithmIdentifier, der(0x04, pkcs1)),
  )
}

function rsaPrivatePkcs1(jwk            )             {
  const integer = (value                    , name        )             =>
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

export function pemToDer(input        )             {
  const normalized = input.replaceAll('\r\n', '\n').trim()
  const match =
    /^-----BEGIN RSA PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END RSA PRIVATE KEY-----$/u.exec(
      normalized,
    )
  if (match === null) throw new InvalidKeyError('Invalid RSA private key PEM')
  const body = match[1] .replaceAll('\n', '')
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

const p384Field = /* @__PURE__ */ BigInt(
  '0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
)
const p384Order = /* @__PURE__ */ BigInt(
  '0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
)
const p384B = /* @__PURE__ */ BigInt(
  '0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
)
const p384Generator = {
  x: /* @__PURE__ */ BigInt(
    '0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
  ),
  y: /* @__PURE__ */ BigInt(
    '0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
  ),
}







function p384Mod(value        )         {
  const reduced = value % p384Field
  return reduced < 0n ? reduced + p384Field : reduced
}

function p384Pow(base        , exponent        )         {
  let result = 1n
  let value = p384Mod(base)
  let remaining = exponent
  while (remaining !== 0n) {
    if ((remaining & 1n) === 1n) result = p384Mod(result * value)
    value = p384Mod(value * value)
    remaining >>= 1n
  }
  return result
}

function p384Double(point           )            {
  if (point.z === 0n || point.y === 0n) return { x: 0n, y: 1n, z: 0n }
  const delta = p384Mod(point.z * point.z)
  const gamma = p384Mod(point.y * point.y)
  const beta = p384Mod(point.x * gamma)
  const alpha = p384Mod(3n * (point.x - delta) * (point.x + delta))
  const x = p384Mod(alpha * alpha - 8n * beta)
  const z = p384Mod((point.y + point.z) * (point.y + point.z) - gamma - delta)
  const y = p384Mod(alpha * (4n * beta - x) - 8n * gamma * gamma)
  return { x, y, z }
}

function p384AddGenerator(point           )            {
  if (point.z === 0n) return { ...p384Generator, z: 1n }
  const zSquared = p384Mod(point.z * point.z)
  const u2 = p384Mod(p384Generator.x * zSquared)
  const s2 = p384Mod(p384Generator.y * point.z * zSquared)
  const h = p384Mod(u2 - point.x)
  const r = p384Mod(2n * (s2 - point.y))
  if (h === 0n) return r === 0n ? p384Double(point) : { x: 0n, y: 1n, z: 0n }
  const i = p384Mod(4n * h * h)
  const j = p384Mod(h * i)
  const v = p384Mod(point.x * i)
  const x = p384Mod(r * r - j - 2n * v)
  const y = p384Mod(r * (v - x) - 2n * point.y * j)
  const z = p384Mod((point.z + h) * (point.z + h) - zSquared - h * h)
  return { x, y, z }
}

function p384PublicFromScalar(scalar            )             {
  const value = bytesToBigInt(scalar)
  if (value === 0n || value >= p384Order) {
    throw new InvalidKeyError('Invalid P-384 secret scalar')
  }




  let point            = { x: 0n, y: 1n, z: 0n }
  for (let bit = 383n; bit >= 0n; bit--) {
    const doubled = p384Double(point)
    const incremented = p384AddGenerator(doubled)
    point = ((value >> bit) & 1n) === 0n ? doubled : incremented
  }
  if (point.z === 0n) throw new InvalidKeyError('Invalid P-384 secret scalar')
  const inverse = p384Pow(point.z, p384Field - 2n)
  const inverseSquared = p384Mod(inverse * inverse)
  const x = p384Mod(point.x * inverseSquared)
  const y = p384Mod(point.y * inverseSquared * inverse)
  if (p384Mod(y * y) !== p384Mod(x * x * x - 3n * x + p384B)) {
    throw new InvalidKeyError('Invalid derived P-384 public key')
  }
  return concat(Uint8Array.of(0x04), bigIntToBytes(x, 48), bigIntToBytes(y, 48))
}

export function decompressP384(compressed            )             {
  if (compressed.byteLength !== 49 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new InvalidKeyError('Invalid P-384 public key')
  }
  const x = bytesToBigInt(compressed.subarray(1))
  if (x >= p384Field) throw new InvalidKeyError('Invalid P-384 public key')
  const ordinate = p384Mod(x * x * x - 3n * x + p384B)
  let y = p384Pow(ordinate, (p384Field + 1n) / 4n)
  if (p384Mod(y * y) !== ordinate) throw new InvalidKeyError('Invalid P-384 public key')
  if (Number(y & 1n) !== (compressed[0]  & 1)) y = p384Field - y
  return concat(Uint8Array.of(0x04), bigIntToBytes(x, 48), bigIntToBytes(y, 48))
}

function p384PrivatePkcs8(scalar            , publicKey             )             {
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

function p384PublicSpki(compressed            )             {
  return der(0x30, concat(p384AlgorithmIdentifier, der(0x03, concat(Uint8Array.of(0), compressed))))
}

export function compressP384(raw            )             {
  if (raw.byteLength !== 97 || raw[0] !== 0x04)
    throw new InvalidKeyError('Invalid P-384 public key')
  return concat(Uint8Array.of(0x02 | (raw[96]  & 1)), raw.subarray(1, 49))
}

function ed25519PrivatePkcs8(seed            )             {
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

export function jwkBytes(value                    , name        )             {
  if (value === undefined) throw new InvalidKeyError(`Missing ${name} in exported key`)
  return decodeBase64url(value, name)
}

function assertRsaPssKey(key           , type                      )       {
  if (key.type !== type) throw new InvalidKeyError(`Expected an RSA-PSS ${type} key`)
  const algorithm = key.algorithm                         
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
  material            ,
  extractable          = false,
)                     {
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
  material            ,
  extractable          = false,
)                     {
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

async function generateRsaPssKeyPair(extractable         )                         {
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
      )                          ,
  )
}

async function exportRsaPssPrivatePkcs1(key           )                      {
  assertRsaPssKey(key, 'private')
  return rsaPrivatePkcs1(
    await webCryptoOperation('RSA-PSS', () => crypto.subtle.exportKey('jwk', key)),
  )
}

async function exportRsaPssPublicSpki(key           )                      {
  assertRsaPssKey(key, 'public')
  return new Uint8Array(
    await webCryptoOperation('RSA-PSS', () => crypto.subtle.exportKey('spki', key)),
  )
}



function rsaPublicJwk(jwk            )             {
  return { kty: jwk.kty, n: jwk.n, e: jwk.e, ext: true, key_ops: ['verify'] }              
}

function curvePublicJwk(jwk            )             {
  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    ext: true,
    key_ops: ['verify'],
  }              
}

async function getPublicKeyByExport(key           , toPublicJwk           )                     {
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

async function getPublicCryptoKey(key           , toPublicJwk           )                     {
  const publicKey = (await webCryptoOperation(key.algorithm.name, () =>

    crypto.subtle.getPublicKey?.(key, ['verify']),
  ))                         
  return publicKey ?? (await getPublicKeyByExport(key, toPublicJwk))
}

async function exportRawPublicCryptoKey(key           )                      {
  return new Uint8Array(
    await webCryptoOperation(key.algorithm.name, () => crypto.subtle.exportKey('raw', key)),
  )
}


export async function importRsaPublicCryptoKey(key           )                        {
  assertRsaPublicCryptoKey(key)
  const material = key.extractable ? await exportRsaPssPublicSpki(key) : undefined
  return new PublicKeyImpl(1, material, key)
}


export async function importEd25519PublicCryptoKey                 (
  version   ,
  key           ,
)                        {
  assertEd25519PublicCryptoKey(key)
  const material = key.extractable ? await exportRawPublicCryptoKey(key) : undefined
  return new PublicKeyImpl(version, material, key)
}


export async function importP384PublicCryptoKey(key           )                        {
  assertP384PublicCryptoKey(key)
  if (!key.extractable) {
    throw new InvalidKeyError('v3.public requires an extractable public CryptoKey')
  }
  const material = compressP384(await exportRawPublicCryptoKey(key))
  return new PublicKeyImpl(3, material, key)
}


export async function importRsaSecretCryptoKey(key           )                        {
  assertRsaSecretCryptoKey(key)
  const publicKey = await getPublicCryptoKey(key, rsaPublicJwk)
  const publicMaterial = await exportRsaPssPublicSpki(publicKey)
  const material = key.extractable ? await exportRsaPssPrivatePkcs1(key) : undefined
  return new SecretKeyImpl(1, key, material, publicMaterial, undefined, publicKey)
}


export async function importEd25519SecretCryptoKey                 (
  version   ,
  key           ,
)                        {
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


export async function importP384SecretCryptoKey(key           )                        {
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
  material            ,
  extractable         ,
)                        {
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
    const publicJwk             = {
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
  extractable         ,
)                                                                {
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

export async function p384RawPublicFromSecret(
  material            ,
  algorithm                  ,
  usage                       ,
)                      {
  checkBytes(material, 'material', 48)
  const scalar = bytesToBigInt(material)
  if (scalar === 0n || scalar >= p384Order) {
    throw new InvalidKeyError('Invalid P-384 secret scalar')
  }
  try {
    const key = await webCryptoOperation(`${algorithm} with P-384`, () =>
      crypto.subtle.importKey(
        'pkcs8',
        webCryptoBytes(p384PrivatePkcs8(material)),
        { name: algorithm, namedCurve: 'P-384' },
        true,
        [usage],
      ),
    )
    const jwk = await webCryptoOperation(`${algorithm} with P-384`, () =>
      crypto.subtle.exportKey('jwk', key),
    )
    return concat(Uint8Array.of(0x04), jwkBytes(jwk.x, 'x'), jwkBytes(jwk.y, 'y'))
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    const raw = p384PublicFromScalar(material)
    try {
      await webCryptoOperation(`${algorithm} with P-384`, () =>
        crypto.subtle.importKey(
          'pkcs8',
          webCryptoBytes(p384PrivatePkcs8(material, raw)),
          { name: algorithm, namedCurve: 'P-384' },
          false,
          [usage],
        ),
      )
    } catch (cause) {
      if (cause instanceof UnsupportedAlgorithmError) throw cause
      throw new InvalidKeyError('Invalid P-384 secret key', { cause })
    }
    return raw
  }
}

export async function importP384SecretKey(
  material            ,
  extractable         ,
)                        {
  const raw = await p384RawPublicFromSecret(material, 'ECDSA', 'sign')
  const cryptoKey = await webCryptoOperation('ECDSA with P-384', () =>
    crypto.subtle.importKey(
      'pkcs8',
      webCryptoBytes(p384PrivatePkcs8(material, raw)),
      { name: 'ECDSA', namedCurve: 'P-384' },
      extractable,
      ['sign'],
    ),
  )
  const publicMaterial = compressP384(raw)
  const publicKey = await p384PublicCryptoKey(publicMaterial, 'ECDSA', ['verify'], true)
  return new SecretKeyImpl(
    3,
    cryptoKey,
    extractable ? material : undefined,
    publicMaterial,
    raw,
    publicKey,
  )
}

async function importEd25519PrivateKey(seed            , extractable         )                     {
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

export async function importEd25519SecretKey                 (
  version   ,
  material            ,
  extractable         ,
)                        {
  checkBytes(material, 'material', 64)
  const seed = material.subarray(0, 32)
  let key           
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
  extractable         ,
)                                                                {
  const generated = await webCryptoOperation(
    'ECDSA with P-384',
    () =>
      crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, extractable, [
        'sign',
        'verify',
      ])                          ,
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

export async function generateEd25519KeyPair                 (
  version   ,
  extractable         ,
)                                                                {
  const generated = await webCryptoOperation(
    'Ed25519',
    () =>
      crypto.subtle.generateKey('Ed25519', extractable, [
        'sign',
        'verify',
      ])                          ,
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

export async function importRsaPublicKey(material            )                        {
  checkBytes(material, 'material')
  let cryptoKey           
  try {
    cryptoKey = await importRsaPssPublicKey(material, true)
    const algorithm = cryptoKey.algorithm                         
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
  material            ,
  algorithm                  ,
  usages            ,
  extractable          = false,
)                     {
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
  data                                            ,
  algorithm                  ,
  usage                       ,
)                     {
  if ('cryptoKey' in data) return data.cryptoKey
  const publicMaterial = data.publicMaterial
  try {
    return await webCryptoOperation(`${algorithm} with P-384`, () =>
      crypto.subtle.importKey(
        'pkcs8',
        webCryptoBytes(p384PrivatePkcs8(data.material, decompressP384(publicMaterial))),
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

export async function importP384PublicKey(material            )                        {
  checkBytes(material, 'material', 49)
  const cryptoKey = await p384PublicCryptoKey(material, 'ECDSA', ['verify'], true)
  return new PublicKeyImpl(3, material, cryptoKey)
}

export async function importEd25519PublicKey                 (
  version   ,
  material            ,
)                        {
  checkBytes(material, 'material', 32)
  let cryptoKey           
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
  material            ,
  extractable          = false,
)                     {
  try {
    return await webCryptoOperation('Ed25519', () =>
      crypto.subtle.importKey('raw', webCryptoBytes(material), 'Ed25519', extractable, ['verify']),
    )
  } catch (cause) {
    if (cause instanceof UnsupportedAlgorithmError) throw cause
    throw new InvalidKeyError('Invalid Ed25519 public key', { cause })
  }
}

function tokenHeader(version         , purpose                    )             {
  return ascii(`v${version}.${purpose}.`)
}

export async function encryptV1Local(
  key                        ,
  message            ,
  footer            ,
)                      {
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
  key                        ,
  message            ,
  footer            ,
  implicit            ,
)                      {
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
  key                        ,
  payload            ,
  footer            ,
)                      {
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
  key                        ,
  payload            ,
  footer            ,
  implicit            ,
)                      {
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

function bytesToBigInt(input            )         {
  let value = 0n
  for (const byte of input) value = (value << 8n) | BigInt(byte)
  return value
}

function bigIntToBytes(value        , length        )             {
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

function normalizeP384Signature(signature            )             {
  if (signature.byteLength !== 96) throw new InvalidTokenError('Invalid P-384 signature length')
  const s = bytesToBigInt(signature.subarray(48))
  if (s <= p384Order / 2n) return signature
  return concat(signature.subarray(0, 48), bigIntToBytes(p384Order - s, 48))
}

function publicMaterial(data                        )             {
  if (data.material === undefined) throw new InvalidKeyError('Public key material is not available')
  return data.material
}

export async function signV1Public(
  data                  ,
  message            ,
  footer            ,
)                      {
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
  data                  ,
  message            ,
  signature            ,
  footer            ,
)                   {
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
  data                  ,
  message            ,
  footer            ,
  implicit            ,
)                      {
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
  data                  ,
  message            ,
  signature            ,
  footer            ,
  implicit            ,
)                   {
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
  data                      ,
  pieces              ,
)                      {
  const key = data.cryptoKey
  return new Uint8Array(
    await webCryptoOperation('Ed25519', () =>
      crypto.subtle.sign('Ed25519', key, webCryptoBytes(PAE(pieces))),
    ),
  )
}

async function verifyEd25519Public(
  data                      ,
  signature            ,
  pieces              ,
)                   {
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
  data                  ,
  message            ,
  footer            ,
)                      {
  return await signEd25519Public(data, [tokenHeader(2, 'public'), message, footer])
}

export async function verifyV2Public(
  data                  ,
  message            ,
  signature            ,
  footer            ,
)                   {
  return await verifyEd25519Public(data, signature, [tokenHeader(2, 'public'), message, footer])
}

export async function signV4Public(
  data                  ,
  message            ,
  footer            ,
  implicit            ,
)                      {
  return await signEd25519Public(data, [tokenHeader(4, 'public'), message, footer, implicit])
}

export async function verifyV4Public(
  data                  ,
  message            ,
  signature            ,
  footer            ,
  implicit            ,
)                   {
  return await verifyEd25519Public(data, signature, [
    tokenHeader(4, 'public'),
    message,
    footer,
    implicit,
  ])
}
