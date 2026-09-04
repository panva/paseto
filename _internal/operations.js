import {
  InvalidKeyError,
  InvalidPASERKError,
















} from '../index.js'

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
} from './bytes.js'
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
} from './crypto.js'
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









} from './keys.js'













function paserkHeader(
  version         ,
  type                                                    ,
)         {
  return `k${version}.${type}.`
}

function serializePaserk                   (
  version   ,
  type                                     ,
  material            ,
)         {
  return `${paserkHeader(version, type)}${toB64u(material)}`
}

function parsePaserk(
  input        ,
  version         ,
  type                                     ,
)             {
  if (typeof input !== 'string') throw new TypeError('"paserk" must be a string')
  const header = paserkHeader(version, type)
  if (!input.startsWith(header) || input.slice(header.length).includes('.')) {
    throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  }
  return decodePaserkPayload(input.slice(header.length))
}

function decodePaserkPayload(input        )             {
  try {
    return decodeBase64url(input, 'PASERK payload')
  } catch (cause) {
    throw new InvalidPASERKError('Invalid PASERK payload', { cause })
  }
}

async function importPaserkKey   (
  input        ,
  version         ,
  type                     ,
  importKey                                      ,
)             {
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

async function paserkIdSha384(version       , type              , paserk        )                  {
  const header = paserkHeader(version, type)
  const input = ascii(`${header}${paserk}`)
  const identifier = (await digest('SHA-384', input)).subarray(0, 33)
  return `${header}${toB64u(identifier)}`
}

function standardPaserkIdInput(
  version         ,
  type                                                                                    ,
  paserk        ,
)          {
  const header = paserkHeader(version, type)
  if (!paserk.startsWith(header)) return false
  const payload = paserk.slice(header.length)
  if (payload === '' || payload.includes('.')) return false
  decodePaserkPayload(payload)
  return true
}

function wrappedPaserkIdInput(
  version         ,
  type                              ,
  paserk        ,
)          {
  const header = `k${version}.${type}.`
  if (!paserk.startsWith(header)) return false
  const data = paserk.slice(header.length)
  const delimiter = data.indexOf('.')
  if (delimiter < 1) return false
  const prefix = data.slice(0, delimiter)
  const encryptedKey = data.slice(delimiter + 1)
  return /^[a-z0-9-]+$/u.test(prefix) && encryptedKey !== '' && /^[\x00-\x7f]+$/u.test(encryptedKey)
}

function validateLocalPaserkIdInput(version         , paserk        )       {
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

function validatePublicPaserkIdInput(version         , paserk        )       {
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (!standardPaserkIdInput(version, 'public', paserk)) {
    throw new InvalidPASERKError(
      `Expected a PASERK compatible with ${paserkHeader(version, 'pid')}`,
    )
  }
}

function validateSecretPaserkIdInput(version         , paserk        )       {
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
  version       ,
  type                                      ,
  plaintext            ,
  wrappingKey            ,
)                  {
  const header = ascii(paserkHeader(version, type))
  const nonce = randomBytes(32)
  const temporary = await hmacSha384(wrappingKey, concat(Uint8Array.of(0x80), nonce))

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
  version       ,
  type                                      ,
  serialized        ,
  wrappingKey            ,
  expectedPlaintext                    ,
)                      {
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
  version       ,
  type                          ,
  plaintext            ,
  password            ,
  options                            ,
)                  {
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
  version       ,
  type                          ,
  serialized        ,
  password            ,
  limits                             ,
  expectedPlaintext                    ,
)                      {
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





async function deriveP384SharedSecret(
  privateKey           ,
  publicMaterial            ,
)                      {
  const publicKey = await p384PublicCryptoKey(publicMaterial, 'ECDH', [])
  return new Uint8Array(
    await webCryptoOperation('ECDH with P-384', () =>
      crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 384),
    ),
  )
}

async function generateP384Ephemeral()           


   {
  const pair = await webCryptoOperation(
    'ECDH with P-384',
    () =>
      crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, [
        'deriveBits',
      ])                          ,
  )
  const raw = new Uint8Array(
    await webCryptoOperation('ECDH with P-384', () =>
      crypto.subtle.exportKey('raw', pair.publicKey),
    ),
  )
  return { privateKey: pair.privateKey, publicMaterial: compressP384(raw) }
}

async function sealV3LocalKey(plaintext            , recipient            )                  {
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
  serialized        ,
  recipient                         ,
)                      {
  const input = parsePaserk(serialized, 3, 'seal')
  if (input.byteLength !== 48 + 49 + 32) {
    throw new InvalidPASERKError('Invalid sealed PASERK length')
  }
  const tag = input.subarray(0, 48)
  const ephemeralPublic = input.subarray(48, 97)
  const ciphertext = input.subarray(97)
  const header = ascii(paserkHeader(3, 'seal'))
  const privateKey = await p384PrivateCryptoKey(recipient, 'ECDH', 'deriveBits')
  let shared            
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





function wrappingKey                   (
  version   ,
  material            ,
  extractable         ,
)                 {
  checkBytes(material, 'material', 32)
  return new WrappingKeyImpl(version, material, extractable)
}

function normalizeWrappedRsaSecret(material            )             {
  try {
    const value = decodeUtf8(material)
    if (value.startsWith('-----BEGIN RSA PRIVATE KEY-----')) return pemToDer(value)
  } catch {

  }
  return material
}

function localMaterial(data                       )             {
  if (data.material === undefined) throw new InvalidKeyError('Key material is not available')
  return data.material
}

function secretMaterial(data                                               )             {
  if (data.material === undefined) throw new InvalidKeyError('Key material is not available')
  return data.material
}

function secretPublicMaterial(data   

 )             {
  if (data.publicMaterial === undefined) {
    throw new InvalidKeyError('Public key material is not available')
  }
  return data.publicMaterial
}

function publicMaterial(data                                               )             {
  if (data.material === undefined) throw new InvalidKeyError('Public key material is not available')
  return data.material
}

async function localKeyFromMaterialLegacy                 (
  version   ,
  material            ,
  extractable         ,
)                       {
  const cryptoKey = await importLocalCryptoKey(material)
  return new LocalKeyImpl(version, extractable ? material : undefined, extractable, cryptoKey)
}

function localKeyFromMaterialModern                 (
  version   ,
  material            ,
  extractable         ,
)              {
  return new LocalKeyImpl(version, material, extractable)
}


export function localKeyFromCryptoKey                 (version   , key           )              {
  assertLocalCryptoKey(key)
  return new LocalKeyImpl(version, undefined, key.extractable, key)
}


export function localKeyToCryptoKey                 (version   , key             )            {
  const cryptoKey = localKeyData(key, version).cryptoKey
  if (cryptoKey === undefined) throw new InvalidKeyError('Key is not backed by a CryptoKey')
  return cryptoKey
}


export async function publicKeyFromCryptoKeyV1(key           )                        {
  return await importRsaPublicCryptoKey(key)
}


export async function publicKeyFromCryptoKeyV2(key           )                        {
  return await importEd25519PublicCryptoKey(2, key)
}


export async function publicKeyFromCryptoKeyV3(key           )                        {
  return await importP384PublicCryptoKey(key)
}


export async function publicKeyFromCryptoKeyV4(key           )                        {
  return await importEd25519PublicCryptoKey(4, key)
}


export function publicKeyToCryptoKey                   (version   , key              )            {
  return publicKeyData(key, version).cryptoKey
}


export async function secretKeyFromCryptoKeyV1(key           )                        {
  return await importRsaSecretCryptoKey(key)
}


export async function secretKeyFromCryptoKeyV2(key           )                        {
  return await importEd25519SecretCryptoKey(2, key)
}


export async function secretKeyFromCryptoKeyV3(key           )                        {
  return await importP384SecretCryptoKey(key)
}


export async function secretKeyFromCryptoKeyV4(key           )                        {
  return await importEd25519SecretCryptoKey(4, key)
}


export function secretKeyToCryptoKey                   (version   , key              )            {
  return secretKeyData(key, version).cryptoKey
}

async function generateP384SealingKeyPair(
  extractable         ,
)                                                                              {
  const generated = await webCryptoOperation(
    'ECDH with P-384',
    () =>
      crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, [
        'deriveBits',
      ])                          ,
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

async function importP384SealingPublicKey(material            )                               {
  checkBytes(material, 'material', 49)
  await p384PublicCryptoKey(material, 'ECDH', [])
  return new SealingPublicKeyImpl(3, material)
}

async function importP384SealingSecretKey(
  material            ,
  extractable         ,
)                               {
  const raw = await p384RawPublicFromSecret(material, 'ECDH', 'deriveBits')
  return new SealingSecretKeyImpl(3, material, compressP384(raw), extractable)
}

export async function generateLocalKeyLegacy                 (
  version   ,
  extractable         ,
)                       {
  return await localKeyFromMaterialLegacy(version, randomBytes(32), extractable)
}

export async function generateLocalKeyModern                 (
  version   ,
  extractable         ,
)                       {
  return localKeyFromMaterialModern(version, randomBytes(32), extractable)
}

export async function encryptLocalV1(
  key             ,
  plaintext            ,
  footer            ,
)                      {
  const data = localKeyData(key, 1)
  return await encryptV1Local(data.cryptoKey ?? localMaterial(data), plaintext, footer)
}

export async function decryptLocalV1(
  key             ,
  payload            ,
  footer            ,
)                      {
  const data = localKeyData(key, 1)
  return await decryptV1Local(data.cryptoKey ?? localMaterial(data), payload, footer)
}

export async function encryptLocalV3(
  key             ,
  plaintext            ,
  footer            ,
  implicitAssertion            ,
)                      {
  const data = localKeyData(key, 3)
  return await encryptV3Local(
    data.cryptoKey ?? localMaterial(data),
    plaintext,
    footer,
    implicitAssertion,
  )
}

export async function decryptLocalV3(
  key             ,
  payload            ,
  footer            ,
  implicitAssertion            ,
)                      {
  const data = localKeyData(key, 3)
  return await decryptV3Local(
    data.cryptoKey ?? localMaterial(data),
    payload,
    footer,
    implicitAssertion,
  )
}

function parseLocalKey                   (version   , paserk                )             {
  const material = parsePaserk(paserk, version, 'local')
  if (material.byteLength !== 32) {
    throw new InvalidKeyError(`Invalid k${version}.local key material`)
  }
  return material
}

export async function importLocalKeyLegacy                 (
  version   ,
  paserk                ,
  extractable         ,
)                       {
  return await localKeyFromMaterialLegacy(version, parseLocalKey(version, paserk), extractable)
}

export async function importLocalKeyModern                 (
  version   ,
  paserk                ,
  extractable         ,
)                       {
  return localKeyFromMaterialModern(version, parseLocalKey(version, paserk), extractable)
}

export async function exportLocalKey                   (
  version   ,
  key             ,
)                          {
  const data = localKeyData(key, version)
  requireExtractable(data)
  return serializePaserk(version, 'local', localMaterial(data))                  
}

export async function localPaserkIdLegacy                 (
  version   ,
  paserk                 ,
)                            {
  validateLocalPaserkIdInput(version, paserk)
  return (await paserkIdSha384(version, 'lid', paserk))                    
}

export async function generateWrappingKey                   (
  version   ,
  extractable         ,
)                          {
  return wrappingKey(version, randomBytes(32), extractable)
}

export async function importWrappingKey                   (
  version   ,
  material            ,
  extractable         ,
)                          {
  return wrappingKey(version, material, extractable)
}

export async function exportWrappingKey                   (
  version   ,
  key                ,
)                      {
  const data = wrappingKeyData(key, version)
  requireExtractable(data)
  return copyBytes(data.material)
}

export async function wrapLocalKeyLegacy                 (
  version   ,
  key             ,
  wrapping                ,
)                                        {
  const source = localKeyData(key, version)
  requireExtractable(source)
  return (await wrapPieSha384(
    version,
    'local-wrap.pie',
    localMaterial(source),
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
  ))                                
}

export async function unwrapLocalKeyLegacy                 (
  version   ,
  paserk                              ,
  wrapping                ,
  extractable         ,
)                       {
  const material = await unwrapPieSha384(
    version,
    'local-wrap.pie',
    paserk,
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
    32,
  )
  return await localKeyFromMaterialLegacy(version, material, extractable)
}

export async function wrapLocalKeyWithPasswordLegacy                 (
  version   ,
  key             ,
  password            ,
  options                        ,
)                                         {
  const source = localKeyData(key, version)
  requireExtractable(source)
  return (await wrapPasswordSha384(
    version,
    'local-pw',
    localMaterial(source),
    password,
    options                              ,
  ))                                 
}

export async function unwrapLocalKeyWithPasswordLegacy                 (
  version   ,
  paserk                               ,
  password            ,
  limits                         ,
  extractable         ,
)                       {
  const material = await unwrapPasswordSha384(
    version,
    'local-pw',
    paserk,
    password,
    limits                               ,
    32,
  )
  return await localKeyFromMaterialLegacy(version, material, extractable)
}

export async function generateSealingKeyPairV3(
  extractable         ,
)                                                             {
  return await generateP384SealingKeyPair(extractable)
}

export async function importSealingPublicKeyV3(material            )                               {
  return await importP384SealingPublicKey(material)
}

export async function importSealingSecretKeyV3(
  material            ,
  extractable         ,
)                               {
  return await importP384SealingSecretKey(material, extractable)
}

export async function exportSealingPublicKeyV3(key                     )                      {
  return copyBytes(sealingPublicKeyData(key, 3).material)
}

export async function exportSealingSecretKeyV3(key                     )                      {
  const data = sealingSecretKeyData(key, 3)
  requireExtractable(data)
  return copyBytes(data.material)
}

export async function sealLocalKeyV3(
  key             ,
  recipient                     ,
)                                {
  const source = localKeyData(key, 3)
  requireExtractable(source)
  return (await sealV3LocalKey(
    localMaterial(source),
    sealingPublicKeyData(recipient, 3, 'recipient'),
  ))                        
}

export async function unsealLocalKeyV3(
  paserk                      ,
  recipient                     ,
  extractable         ,
)                       {
  const material = await unsealV3LocalKey(paserk, sealingSecretKeyData(recipient, 3))
  checkBytes(material, 'unsealed local key', 32)
  return await localKeyFromMaterialLegacy(3, material, extractable)
}

export async function generatePublicKeyPairV1(
  extractable         ,
)                                               {
  return await generateRsaKeyPair(extractable)
}

export async function generatePublicKeyPairV2(
  extractable         ,
)                                               {
  return await generateEd25519KeyPair(2, extractable)
}

export async function generatePublicKeyPairV3(
  extractable         ,
)                                               {
  return await generateP384KeyPair(extractable)
}

export async function generatePublicKeyPairV4(
  extractable         ,
)                                               {
  return await generateEd25519KeyPair(4, extractable)
}

export async function signPublicV1(
  key              ,
  message            ,
  footer            ,
)                      {
  return await signV1Public(secretKeyData(key, 1), message, footer)
}

export async function verifyPublicV1(
  key              ,
  message            ,
  signature            ,
  footer            ,
)                   {
  return await verifyV1Public(publicKeyData(key, 1), message, signature, footer)
}

export async function signPublicV2(
  key              ,
  message            ,
  footer            ,
)                      {
  return await signV2Public(secretKeyData(key, 2), message, footer)
}

export async function verifyPublicV2(
  key              ,
  message            ,
  signature            ,
  footer            ,
)                   {
  return await verifyV2Public(publicKeyData(key, 2), message, signature, footer)
}

export async function signPublicV3(
  key              ,
  message            ,
  footer            ,
  implicitAssertion            ,
)                      {
  return await signV3Public(secretKeyData(key, 3), message, footer, implicitAssertion)
}

export async function verifyPublicV3(
  key              ,
  message            ,
  signature            ,
  footer            ,
  implicitAssertion            ,
)                   {
  return await verifyV3Public(publicKeyData(key, 3), message, signature, footer, implicitAssertion)
}

export async function signPublicV4(
  key              ,
  message            ,
  footer            ,
  implicitAssertion            ,
)                      {
  return await signV4Public(secretKeyData(key, 4), message, footer, implicitAssertion)
}

export async function verifyPublicV4(
  key              ,
  message            ,
  signature            ,
  footer            ,
  implicitAssertion            ,
)                   {
  return await verifyV4Public(publicKeyData(key, 4), message, signature, footer, implicitAssertion)
}

export async function importPublicKeyV1(paserk                 )                        {
  return await importPaserkKey(paserk, 1, 'public', importRsaPublicKey)
}

export async function importPublicKeyV2(paserk                 )                        {
  return await importPaserkKey(paserk, 2, 'public', (material) =>
    importEd25519PublicKey(2, material),
  )
}

export async function importPublicKeyV3(paserk                 )                        {
  return await importPaserkKey(paserk, 3, 'public', importP384PublicKey)
}

export async function importPublicKeyV4(paserk                 )                        {
  return await importPaserkKey(paserk, 4, 'public', (material) =>
    importEd25519PublicKey(4, material),
  )
}

export async function exportPublicKey                   (
  version   ,
  key              ,
)                           {
  const data = publicKeyData(key, version)
  requireExtractable(data)
  return serializePaserk(version, 'public', publicMaterial(data))                   
}

export async function importSecretKeyV1(
  paserk                 ,
  extractable         ,
)                        {
  return await importPaserkKey(paserk, 1, 'secret', (material) =>
    importRsaSecretKey(material, extractable),
  )
}

export async function importSecretKeyV2(
  paserk                 ,
  extractable         ,
)                        {
  return await importPaserkKey(paserk, 2, 'secret', (material) =>
    importEd25519SecretKey(2, material, extractable),
  )
}

export async function importSecretKeyV3(
  paserk                 ,
  extractable         ,
)                        {
  return await importPaserkKey(paserk, 3, 'secret', (material) =>
    importP384SecretKey(material, extractable),
  )
}

export async function importSecretKeyV4(
  paserk                 ,
  extractable         ,
)                        {
  return await importPaserkKey(paserk, 4, 'secret', (material) =>
    importEd25519SecretKey(4, material, extractable),
  )
}

export async function exportSecretKey                   (
  version   ,
  key              ,
)                           {
  const data = secretKeyData(key, version)
  requireExtractable(data)
  return serializePaserk(version, 'secret', secretMaterial(data))                   
}

export async function getPublicKey                   (
  version   ,
  key              ,
)                        {
  const data = secretKeyData(key, version)
  return new PublicKeyImpl(version, secretPublicMaterial(data), data.publicCryptoKey)
}

export async function publicPaserkIdLegacy                 (
  version   ,
  paserk                 ,
)                             {
  validatePublicPaserkIdInput(version, paserk)
  return (await paserkIdSha384(version, 'pid', paserk))                     
}

export async function secretPaserkIdLegacy                 (
  version   ,
  paserk                  ,
)                             {
  validateSecretPaserkIdInput(version, paserk)
  return (await paserkIdSha384(version, 'sid', paserk))                     
}

function protectedSecretLength(version       )                     {
  return version === 1 ? undefined : 48
}

export async function wrapSecretKeyLegacy                 (
  version   ,
  key              ,
  wrapping                ,
)                                         {
  const source = secretKeyData(key, version)
  requireExtractable(source)
  return (await wrapPieSha384(
    version,
    'secret-wrap.pie',
    secretMaterial(source),
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
  ))                                 
}

async function importProtectedSecretKey                 (
  version   ,
  material            ,
  extractable         ,
)                        {
  if (version === 1) {
    return (await importRsaSecretKey(
      normalizeWrappedRsaSecret(material),
      extractable,
    ))                
  }
  return (await importP384SecretKey(material, extractable))                
}

export async function unwrapSecretKeyLegacy                 (
  version   ,
  paserk                               ,
  wrapping                ,
  extractable         ,
)                        {
  const material = await unwrapPieSha384(
    version,
    'secret-wrap.pie',
    paserk,
    wrappingKeyData(wrapping, version, 'wrappingKey').material,
    protectedSecretLength(version),
  )
  return await importProtectedSecretKey(version, material, extractable)
}

export async function wrapSecretKeyWithPasswordLegacy                 (
  version   ,
  key              ,
  password            ,
  options                        ,
)                                          {
  const source = secretKeyData(key, version)
  requireExtractable(source)
  return (await wrapPasswordSha384(
    version,
    'secret-pw',
    secretMaterial(source),
    password,
    options                              ,
  ))                                  
}

export async function unwrapSecretKeyWithPasswordLegacy                 (
  version   ,
  paserk                                ,
  password            ,
  limits                         ,
  extractable         ,
)                        {
  const material = await unwrapPasswordSha384(
    version,
    'secret-pw',
    paserk,
    password,
    limits                               ,
    protectedSecretLength(version),
  )
  return await importProtectedSecretKey(version, material, extractable)
}
