import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  publicEncrypt,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto'

export interface K1UnsealedReference {
  plaintext: Uint8Array
  random: Uint8Array
}

const encoder: TextEncoder = new TextEncoder()
const header: Uint8Array = encoder.encode('k1.seal.')

function concat(...inputs: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(inputs.reduce((length, input) => length + input.byteLength, 0))
  let offset = 0
  for (const input of inputs) {
    output.set(input, offset)
    offset += input.byteLength
  }
  return output
}

function base64url(input: Uint8Array): string {
  return Buffer.from(input).toString('base64url')
}

function decodeBase64url(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(input) || input.length % 4 === 1) {
    throw new TypeError('Invalid base64url')
  }
  const output = new Uint8Array(Buffer.from(input, 'base64url'))
  if (base64url(output) !== input) throw new TypeError('Non-canonical base64url')
  return output
}

function sha384(input: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha384').update(input).digest())
}

function hmacSha384(key: Uint8Array, input: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac('sha384', key).update(input).digest())
}

function aesCtr(
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  encrypt: boolean,
): Uint8Array {
  const cipher = encrypt
    ? createCipheriv('aes-256-ctr', key, nonce)
    : createDecipheriv('aes-256-ctr', key, nonce)
  return new Uint8Array(Buffer.concat([cipher.update(input), cipher.final()]))
}

function assertRsa4096(key: KeyObject): void {
  if (
    key.asymmetricKeyType !== 'rsa' ||
    key.asymmetricKeyDetails?.modulusLength !== 4096 ||
    key.asymmetricKeyDetails.publicExponent !== 65_537n
  ) {
    throw new TypeError('PASERK k1.seal requires a 4096-bit RSA key with exponent 65537')
  }
}

function sealParts(
  plaintext: Uint8Array,
  random: Uint8Array,
  ciphertext: Uint8Array,
): { tag: Uint8Array; encrypted: Uint8Array } {
  if (plaintext.byteLength !== 32) throw new TypeError('PASERK local key must be 32 bytes')
  if (random.byteLength !== 512) throw new TypeError('RSA-KEM random value must be 512 bytes')
  if (ciphertext.byteLength !== 512) throw new TypeError('RSA ciphertext must be 512 bytes')
  const ciphertextHash = sha384(ciphertext)
  const encryptionMaterial = hmacSha384(ciphertextHash, concat(Uint8Array.of(0x01), header, random))
  const authenticationKey = hmacSha384(ciphertextHash, concat(Uint8Array.of(0x02), header, random))
  const encrypted = aesCtr(
    encryptionMaterial.subarray(0, 32),
    encryptionMaterial.subarray(32),
    plaintext,
    true,
  )
  const tag = hmacSha384(authenticationKey, concat(header, ciphertext, encrypted))
  return { tag, encrypted }
}

export function sealK1Paserk(
  plaintext: Uint8Array,
  sealingPublicKey: string | Uint8Array,
  random: Uint8Array,
): string {
  const key = createPublicKey(
    typeof sealingPublicKey === 'string' ? sealingPublicKey : Buffer.from(sealingPublicKey),
  )
  assertRsa4096(key)
  if ((random[0]! & 0xc0) !== 0x40) {
    throw new TypeError('RSA-KEM random value must start with binary 01')
  }
  const ciphertext = new Uint8Array(
    publicEncrypt({ key, padding: constants.RSA_NO_PADDING }, random),
  )
  const { tag, encrypted } = sealParts(plaintext, random, ciphertext)
  return `k1.seal.${base64url(concat(tag, encrypted, ciphertext))}`
}

export function unsealK1Paserk(
  paserk: string,
  sealingSecretKey: string | Uint8Array,
): K1UnsealedReference {
  const prefix = 'k1.seal.'
  if (!paserk.startsWith(prefix)) throw new TypeError('Wrong PASERK header')
  const key = createPrivateKey(
    typeof sealingSecretKey === 'string' ? sealingSecretKey : Buffer.from(sealingSecretKey),
  )
  assertRsa4096(key)
  const body = decodeBase64url(paserk.slice(prefix.length))
  if (body.byteLength !== 592) throw new TypeError('Invalid k1.seal length')
  const tag = body.subarray(0, 48)
  const encrypted = body.subarray(48, 80)
  const ciphertext = body.subarray(80)
  const random = new Uint8Array(
    privateDecrypt({ key, padding: constants.RSA_NO_PADDING }, ciphertext),
  )
  const ciphertextHash = sha384(ciphertext)
  const authenticationKey = hmacSha384(ciphertextHash, concat(Uint8Array.of(0x02), header, random))
  const expectedTag = hmacSha384(authenticationKey, concat(header, ciphertext, encrypted))
  if (!timingSafeEqual(tag, expectedTag)) throw new Error('Invalid PASERK authentication tag')
  const encryptionMaterial = hmacSha384(ciphertextHash, concat(Uint8Array.of(0x01), header, random))
  return {
    plaintext: aesCtr(
      encryptionMaterial.subarray(0, 32),
      encryptionMaterial.subarray(32),
      encrypted,
      false,
    ),
    random,
  }
}
