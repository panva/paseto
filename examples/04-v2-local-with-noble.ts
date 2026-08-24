import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
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
// Application code imports this type from 'paseto/v2/local'.
import type { LocalKey } from '../v2/local.ts'

const header = new TextEncoder().encode('v2.local.')
const keyMaterial = new WeakMap<NobleLocalKey, Uint8Array>()

class NobleLocalKey implements LocalKey {
  readonly algorithm = Object.freeze({ name: 'PASETO v2.local' as const })
  readonly extractable: boolean
  readonly kind = 'local' as const
  readonly type = 'secret' as const
  readonly version = 2 as const

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
  if (material === undefined) {
    throw new InvalidKeyError('Key was not created by this v2.local implementation')
  }
  return material
}

function concat(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.byteLength + right.byteLength)
  output.set(left)
  output.set(right, left.byteLength)
  return output
}

const GenerateKeyFactory = LocalGenerateKey<2, NobleLocalKey>({
  version: 2,
  run: async (extractable) => NobleLocalKey.generate(extractable),
})

const EncryptFactory = LocalEncrypt<2, NobleLocalKey>({
  version: 2,
  run: async (key, plaintext, footer) => {
    const material = getKeyMaterial(key)
    const nonce = blake2b(plaintext, { dkLen: 24, key: randomBytes(24) })
    const ciphertext = xchacha20poly1305(material, nonce, PAE([header, nonce, footer])).encrypt(
      plaintext,
    )
    return concat(nonce, ciphertext)
  },
})

const DecryptFactory = LocalDecrypt<2, NobleLocalKey>({
  version: 2,
  run: async (key, payload, footer) => {
    const material = getKeyMaterial(key)
    if (payload.byteLength < 40) {
      throw new InvalidTokenError('Invalid v2.local payload')
    }
    const nonce = payload.subarray(0, 24)
    const ciphertext = payload.subarray(24)
    try {
      return xchacha20poly1305(material, nonce, PAE([header, nonce, footer])).decrypt(ciphertext)
    } catch (cause) {
      throw new InvalidTokenError('Token authentication failed', { cause })
    }
  },
})

const v2 = new LocalProtocol(GenerateKeyFactory, EncryptFactory, DecryptFactory)
const key = await v2.GenerateKey()
const footer = new TextEncoder().encode('key-id:example')
const token = await v2.Encrypt(key, { sub: 'alice', role: 'admin' }, { footer })
const { claims } = await v2.Decrypt(key, token, {
  footer,
  subject: 'alice',
  requiredClaims: ['role'],
})

console.log(key.extractable) // false
console.log(token)
console.log(claims)
