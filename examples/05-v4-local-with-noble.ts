import { xchacha20 } from '@noble/ciphers/chacha.js'
import { equalBytes } from '@noble/ciphers/utils.js'
import { blake2b } from '@noble/hashes/blake2.js'
import { randomBytes } from '@noble/hashes/utils.js'

// Application code imports these from 'paseto'.
import {
  InvalidKeyError,
  InvalidTokenError,
  LocalDecrypt,
  LocalEncrypt,
  LocalGenerateKey,
  LocalProtocol,
  PAE,
} from '../index.ts'
// Application code imports this type from 'paseto/v4/local'.
import type { LocalKey } from '../v4/local.ts'

const encoder = new TextEncoder()
const header = encoder.encode('v4.local.')
const encryptionLabel = encoder.encode('paseto-encryption-key')
const authenticationLabel = encoder.encode('paseto-auth-key-for-aead')

function concat(...inputs: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(inputs.reduce((length, input) => length + input.byteLength, 0))
  let offset = 0
  for (const input of inputs) {
    output.set(input, offset)
    offset += input.byteLength
  }
  return output
}

const keyMaterial = new WeakMap<NobleLocalKey, Uint8Array>()

class NobleLocalKey implements LocalKey {
  readonly algorithm = Object.freeze({ name: 'PASETO v4.local' as const })
  readonly extractable: boolean
  readonly kind = 'local' as const
  readonly type = 'secret' as const
  readonly version = 4 as const

  private constructor(material: Uint8Array, extractable: boolean) {
    this.extractable = extractable
    keyMaterial.set(this, Uint8Array.from(material))
    Object.freeze(this)
  }

  static generate(extractable: boolean): NobleLocalKey {
    return new NobleLocalKey(randomBytes(32), extractable)
  }
}

function getKeyMaterial(key: NobleLocalKey): Uint8Array {
  const material = keyMaterial.get(key)
  if (material === undefined)
    throw new InvalidKeyError('Key was not created by this implementation')
  return material
}

function keyedBlake2b(input: Uint8Array, key: Uint8Array, length: number): Uint8Array {
  return blake2b(input, { key, dkLen: length })
}

function encryptionMaterial(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return keyedBlake2b(concat(encryptionLabel, nonce), key, 56)
}

function authenticationKey(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return keyedBlake2b(concat(authenticationLabel, nonce), key, 32)
}

const GenerateKeyFactory = LocalGenerateKey<4, NobleLocalKey>({
  version: 4,
  run: async (extractable) => NobleLocalKey.generate(extractable),
})

const EncryptFactory = LocalEncrypt<4, NobleLocalKey>({
  version: 4,
  run: async (key, plaintext, footer, implicitAssertion) => {
    const material = getKeyMaterial(key)
    const nonce = randomBytes(32)
    const temporary = encryptionMaterial(material, nonce)
    const ciphertext = xchacha20(temporary.subarray(0, 32), temporary.subarray(32), plaintext)
    const tag = keyedBlake2b(
      PAE([header, nonce, ciphertext, footer, implicitAssertion]),
      authenticationKey(material, nonce),
      32,
    )

    return concat(nonce, ciphertext, tag)
  },
})

const DecryptFactory = LocalDecrypt<4, NobleLocalKey>({
  version: 4,
  run: async (key, payload, footer, implicitAssertion) => {
    if (payload.byteLength < 64) throw new InvalidTokenError('Truncated v4.local payload')

    const material = getKeyMaterial(key)
    const nonce = payload.subarray(0, 32)
    const ciphertext = payload.subarray(32, -32)
    const tag = payload.subarray(-32)
    const expectedTag = keyedBlake2b(
      PAE([header, nonce, ciphertext, footer, implicitAssertion]),
      authenticationKey(material, nonce),
      32,
    )

    if (!equalBytes(tag, expectedTag)) {
      throw new InvalidTokenError('Token authentication failed')
    }

    const temporary = encryptionMaterial(material, nonce)
    return xchacha20(temporary.subarray(0, 32), temporary.subarray(32), ciphertext)
  },
})

const v4 = new LocalProtocol(GenerateKeyFactory, EncryptFactory, DecryptFactory)
const key = await v4.GenerateKey()
const implicitAssertion = encoder.encode('tenant:example')

const token = await v4.Encrypt(key, { sub: 'alice', role: 'admin' }, { implicitAssertion })
const { claims } = await v4.Decrypt(key, token, {
  implicitAssertion,
  subject: 'alice',
  requiredClaims: ['role'],
})

console.log(key.extractable) // false
console.log(token)
console.log(claims)
