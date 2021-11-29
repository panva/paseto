import random from './runtime/random.js'
import * as base64url from './runtime/base64url.js'
import * as gnrt from './runtime/generate.js'
import pack from './pack.js'
import pae from './pae.js'
import * as ed25519 from './runtime/ed25519.js'
import { XChaCha20Poly1305 } from './stablelib/xchacha20poly1305.js'
import { hash as blake2b } from './stablelib/blake2b.js'
import { streamXOR as xchacha20 } from './stablelib/xchacha20.js'
import timingSafeEqual from './runtime/timing_safe_equal.js'
import hmac384 from './runtime/hmac384.js'
import hkdf384 from './runtime/hkdf384.js'
import * as aesctr from './runtime/aesctr.js'
import * as rsa from './runtime/rsa.js'
import * as ec from './runtime/ec.js'
import * as errors from './errors.js'

const kAssertion = Symbol('kAssertion')
const kGenKeyPair = Symbol('kGenKeyPair')
const kGenSecret = Symbol('kGenSecret')
const kPurpose = Symbol('kPurpose')
const kSeal = Symbol('kSeal')
const kUnseal = Symbol('kUnseal')
const kNonce = Symbol('kNonce')
const kVersion = Symbol('kVersion')

const buf = TextEncoder.prototype.encode.bind(new TextEncoder())

interface GenerateKeyPairFn {
  (): Promise<KeyPair>
}

interface GenerateSecretFn {
  (): string
}

interface GenerateNonce {
  (): Uint8Array
}

interface VersionPurpose {
  readonly [kNonce]?: GenerateNonce
  readonly [kPurpose]: string
  readonly [kVersion]: number
  readonly [kAssertion]: boolean
  readonly [kGenKeyPair]?: GenerateKeyPairFn
  readonly [kGenSecret]?: GenerateSecretFn
  readonly [kSeal]: (
    key: string,
    payload: Uint8Array,
    footer: Uint8Array,
    assertion: Uint8Array,
  ) => Promise<string>
  readonly [kUnseal]: (
    key: string,
    payload: Uint8Array,
    footer: Uint8Array,
    assertion: Uint8Array,
  ) => Promise<UnsealResult>
}

export interface KeyPair {
  public: string
  secret: string
}

interface VersionPurposePublic extends VersionPurpose {
  readonly [kGenKeyPair]: GenerateKeyPairFn
  readonly [kGenSecret]?: never
  readonly [kNonce]?: never
}

interface VersionPurposeLocal extends VersionPurpose {
  readonly [kGenSecret]: GenerateSecretFn
  readonly [kGenKeyPair]?: never
  readonly [kNonce]: GenerateNonce
}

function checkLocalKey(this: VersionPurpose, key: string) {
  if (!key.match(new RegExp(`^k${this[kVersion]}\\.local\\.[a-zA-Z\\d_-]+$`)))
    throw new errors.PASERKInvalid('TODO')
  const secret = base64url.decode(key.split('.')[2])
  if (secret.byteLength !== 32) throw new errors.PASERKInvalid('TODO')
  return secret
}

export const V1Local: VersionPurposeLocal = {
  [kNonce]: () => random(new Uint8Array(32)),
  [kAssertion]: false,
  [kGenSecret]: () => `k1.local.${base64url.encode(random(new Uint8Array(32)))}`,
  [kPurpose]: 'local',
  [kVersion]: 1,
  [kSeal]: async function (key, payload, footer) {
    const secret = checkLocalKey.call(this, key)

    const n = (await hmac384(payload, this[kNonce]())).subarray(0, 32)
    const salt = n.subarray(0, 16)
    const [ek, ak] = await Promise.all([
      hkdf384(secret, salt, buf('paseto-encryption-key'), 32),
      hkdf384(secret, salt, buf('paseto-auth-key-for-aead'), 32),
    ])
    const c = await aesctr.encrypt(payload, ek, n.subarray(16))

    const preAuth = pae(buf('v1.local.'), n, c, footer)
    const t = await hmac384(preAuth, ak)

    return pack(this[kVersion], this[kPurpose], footer, n, c, t)
  },
  [kUnseal]: async function (key, payload, footer) {
    const secret = checkLocalKey.call(this, key)

    const n = payload.subarray(0, 32)
    const t = payload.subarray(-48)
    const c = payload.subarray(32, -48)

    const salt = n.subarray(0, 16)
    const [ek, ak] = await Promise.all([
      hkdf384(secret, salt, buf('paseto-encryption-key'), 32),
      hkdf384(secret, salt, buf('paseto-auth-key-for-aead'), 32),
    ])

    const preAuth = pae(buf('v1.local.'), n, c, footer)
    const t2 = await hmac384(preAuth, ak)
    if (!timingSafeEqual(t, t2)) throw new errors.PASETOSignatureVerificationFailed()

    try {
      return { payload: await aesctr.decrypt(c, ek, n.subarray(16)), footer }
    } catch {
      throw new errors.PASETODecryptionFailed()
    }
  },
}

export const V2Local: VersionPurposeLocal = {
  [kNonce]: () => random(new Uint8Array(24)),
  [kAssertion]: false,
  [kGenSecret]: () => `k2.local.${base64url.encode(random(new Uint8Array(32)))}`,
  [kPurpose]: 'local',
  [kVersion]: 2,
  [kSeal]: async function (key, payload, footer) {
    const secret = checkLocalKey.call(this, key)

    const n = blake2b(payload, 24, { key: this[kNonce]() })
    const preAuth = pae(buf('v2.local.'), n, footer)
    const c = new XChaCha20Poly1305(secret).seal(n, payload, preAuth)

    return pack(this[kVersion], this[kPurpose], footer, n, c)
  },
  [kUnseal]: async function (key, payload, footer) {
    const secret = checkLocalKey.call(this, key)

    const n = payload.subarray(0, 24)
    const c = payload.subarray(24)
    const preAuth = pae(buf('v2.local.'), n, footer)

    let plaintext: Uint8Array | null
    try {
      plaintext = new XChaCha20Poly1305(secret).open(n, c, preAuth)
    } catch {
      throw new errors.PASETODecryptionFailed()
    }
    if (!plaintext) throw new errors.PASETODecryptionFailed()

    return { payload: plaintext, footer }
  },
}

export const V3Local: VersionPurposeLocal = {
  [kNonce]: () => random(new Uint8Array(32)),
  [kAssertion]: true,
  [kGenSecret]: () => `k3.local.${base64url.encode(random(new Uint8Array(32)))}`,
  [kPurpose]: 'local',
  [kVersion]: 3,
  [kSeal]: async function (key, payload, footer, assertion) {
    const secret = checkLocalKey.call(this, key)

    const n = this[kNonce]()
    const [tmp, ak] = await Promise.all([
      hkdf384(
        secret,
        new Uint8Array(),
        new Uint8Array([...buf('paseto-encryption-key'), ...n]),
        48,
      ),
      hkdf384(
        secret,
        new Uint8Array(),
        new Uint8Array([...buf('paseto-auth-key-for-aead'), ...n]),
        48,
      ),
    ])
    const ek = tmp.subarray(0, 32)
    const n2 = tmp.subarray(32)
    const c = await aesctr.encrypt(payload, ek, n2)
    const preAuth = pae(buf('v3.local.'), n, c, footer, assertion)
    const t = await hmac384(preAuth, ak)

    return pack(this[kVersion], this[kPurpose], footer, n, c, t)
  },
  [kUnseal]: async function (key, payload, footer, assertion) {
    const secret = checkLocalKey.call(this, key)

    const n = payload.subarray(0, 32)
    const t = payload.subarray(-48)
    const c = payload.subarray(32, -48)
    const [tmp, ak] = await Promise.all([
      hkdf384(
        secret,
        new Uint8Array(),
        new Uint8Array([...buf('paseto-encryption-key'), ...n]),
        48,
      ),
      hkdf384(
        secret,
        new Uint8Array(),
        new Uint8Array([...buf('paseto-auth-key-for-aead'), ...n]),
        48,
      ),
    ])
    const ek = tmp.subarray(0, 32)
    const n2 = tmp.subarray(32)
    const preAuth = pae(buf('v3.local.'), n, c, footer, assertion)
    const t2 = await hmac384(preAuth, ak)
    if (!timingSafeEqual(t, t2)) throw new errors.PASETODecryptionFailed()

    try {
      return { payload: await aesctr.decrypt(c, ek, n2), footer }
    } catch {
      throw new errors.PASETODecryptionFailed()
    }
  },
}

export const V4Local: VersionPurposeLocal = {
  [kNonce]: () => random(new Uint8Array(32)),
  [kAssertion]: true,
  [kGenSecret]: () => `k4.local.${base64url.encode(random(new Uint8Array(32)))}`,
  [kPurpose]: 'local',
  [kVersion]: 4,
  [kSeal]: async function (key, payload, footer, assertion) {
    const secret = checkLocalKey.call(this, key)

    const n = this[kNonce]()
    const tmp = blake2b(new Uint8Array([...buf('paseto-encryption-key'), ...n]), 56, {
      key: secret,
    })
    const ek = tmp.subarray(0, 32)
    const n2 = tmp.subarray(32)
    const ak = blake2b(new Uint8Array([...buf('paseto-auth-key-for-aead'), ...n]), 32, {
      key: secret,
    })

    const c = xchacha20(ek, n2, payload, new Uint8Array(payload.byteLength))
    const preAuth = pae(buf('v4.local.'), n, c, footer, assertion)
    const t = blake2b(preAuth, 32, { key: ak })

    return pack(this[kVersion], this[kPurpose], footer, n, c, t)
  },
  [kUnseal]: async function (key, payload, footer, assertion) {
    const secret = checkLocalKey.call(this, key)

    const n = payload.subarray(0, 32)
    const t = payload.subarray(-32)
    const c = payload.subarray(32, -32)

    const tmp = blake2b(new Uint8Array([...buf('paseto-encryption-key'), ...n]), 56, {
      key: secret,
    })
    const ek = tmp.subarray(0, 32)
    const n2 = tmp.subarray(32)
    const ak = blake2b(new Uint8Array([...buf('paseto-auth-key-for-aead'), ...n]), 32, {
      key: secret,
    })

    const preAuth = pae(buf('v4.local.'), n, c, footer, assertion)
    const t2 = blake2b(preAuth, 32, { key: ak })
    if (!timingSafeEqual(t, t2)) throw new errors.PASETODecryptionFailed()

    try {
      return { payload: xchacha20(ek, n2, c, new Uint8Array(c.byteLength)), footer }
    } catch {
      throw new errors.PASETODecryptionFailed()
    }
  },
}

export const V1Public: VersionPurposePublic = {
  [kAssertion]: false,
  [kGenKeyPair]: gnrt.v1public,
  [kPurpose]: 'public',
  [kVersion]: 1,
  [kSeal]: async function (key, payload, footer) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.secret\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const secretKey = base64url.decode(key.split('.')[2])

    const m2 = pae(buf('v1.public.'), payload, footer)
    const sig = await rsa.sign(m2, secretKey)

    return pack(this[kVersion], this[kPurpose], footer, payload, sig)
  },
  [kUnseal]: async function (key, payload, footer) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.public\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const publicKey = base64url.decode(key.split('.')[2])

    const m = payload.subarray(0, -256)
    const s = payload.subarray(-256)
    const m2 = pae(buf('v1.public.'), m, footer)

    if (!(await rsa.verify(m2, publicKey, s))) {
      throw new errors.PASETOSignatureVerificationFailed()
    }

    return { payload: m, footer }
  },
}

export const V2Public: VersionPurposePublic = {
  [kAssertion]: false,
  [kGenKeyPair]: gnrt.v2public,
  [kPurpose]: 'public',
  [kVersion]: 2,
  [kSeal]: async function (key, payload, footer) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.secret\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const secretKey = base64url.decode(key.split('.')[2])
    if (secretKey.byteLength !== 64) throw new errors.PASERKInvalid('TODO')

    const m2 = pae(buf('v2.public.'), payload, footer)
    const sig = await ed25519.sign(m2, secretKey)

    return pack(this[kVersion], this[kPurpose], footer, payload, sig)
  },
  [kUnseal]: async function (key, payload, footer) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.public\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const publicKey = base64url.decode(key.split('.')[2])
    if (publicKey.byteLength !== 32) throw new TypeError('TODO')

    const m = payload.subarray(0, -64)
    const s = payload.subarray(-64)
    const m2 = pae(buf('v2.public.'), m, footer)

    if (!(await ed25519.verify(m2, publicKey, s))) {
      throw new errors.PASETOSignatureVerificationFailed()
    }

    return { payload: m, footer }
  },
}

export const V3Public: VersionPurposePublic = {
  [kAssertion]: true,
  [kGenKeyPair]: gnrt.v3public,
  [kPurpose]: 'public',
  [kVersion]: 3,
  [kSeal]: async function (key, payload, footer, assertion) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.secret\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const secretKey = base64url.decode(key.split('.')[2])
    if (secretKey.byteLength !== 48) throw new errors.PASERKInvalid('TODO')

    const publicKey = await ec.eoFromSk(secretKey)
    const m2 = pae(publicKey, buf('v3.public.'), payload, footer, assertion)
    const sig = await ec.sign(m2, secretKey)

    return pack(this[kVersion], this[kPurpose], footer, payload, sig)
  },
  [kUnseal]: async function (key, payload, footer, assertion) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.public\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const publicKey = base64url.decode(key.split('.')[2])
    if (publicKey.byteLength !== 49 || (publicKey[0] !== 0x02 && publicKey[0] !== 0x03))
      throw new TypeError('TODO')

    const m = payload.subarray(0, -96)
    const s = payload.subarray(-96)
    const m2 = pae(publicKey, buf('v3.public.'), m, footer, assertion)

    if (!(await ec.verify(m2, publicKey, s))) {
      throw new errors.PASETOSignatureVerificationFailed()
    }

    return { payload: m, footer }
  },
}

export const V4Public: VersionPurposePublic = {
  [kAssertion]: true,
  [kGenKeyPair]: gnrt.v4public,
  [kPurpose]: 'public',
  [kVersion]: 4,
  [kSeal]: async function (key, payload, footer, assertion) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.secret\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const secretKey = base64url.decode(key.split('.')[2])
    if (secretKey.byteLength !== 64) throw new errors.PASERKInvalid('TODO')

    const m2 = pae(buf('v4.public.'), payload, footer, assertion)
    const sig = await ed25519.sign(m2, secretKey)

    return pack(this[kVersion], this[kPurpose], footer, payload, sig)
  },
  [kUnseal]: async function (key, payload, footer, assertion) {
    if (!key.match(new RegExp(`^k${this[kVersion]}\\.public\\.[a-zA-Z\\d_-]+$`)))
      throw new errors.PASERKInvalid('TODO')
    const publicKey = base64url.decode(key.split('.')[2])
    if (publicKey.byteLength !== 32) throw new TypeError('TODO')

    const m = payload.subarray(0, -64)
    const s = payload.subarray(-64)
    const m2 = pae(buf('v4.public.'), m, footer, assertion)

    if (!(await ed25519.verify(m2, publicKey, s))) {
      throw new errors.PASETOSignatureVerificationFailed()
    }

    return { payload: m, footer }
  },
}

export function generate(config: VersionPurposeLocal): GenerateSecretFn
export function generate(config: VersionPurposePublic): GenerateKeyPairFn
export function generate(
  config: VersionPurposeLocal | VersionPurposePublic,
): GenerateSecretFn | GenerateKeyPairFn {
  if (!config || typeof config !== 'object') throw new TypeError('TODO')
  if (config[kGenKeyPair] !== undefined)
    return (<VersionPurposePublic>config)[kGenKeyPair].bind(config)
  if (config[kGenSecret] !== undefined)
    return (<VersionPurposeLocal>config)[kGenSecret].bind(config)
  throw new TypeError('TODO')
}

interface SealFn {
  (key: string, payload?: Uint8Array, footer?: Uint8Array, assertion?: Uint8Array): Promise<string>
}

interface UnsealResult {
  payload: Uint8Array
  footer: Uint8Array
}

interface UnsealFn {
  (key: string, token: string, assertion?: Uint8Array): Promise<UnsealResult>
}

export function seal(config: VersionPurposeLocal | VersionPurposePublic): SealFn {
  return async (
    key,
    payload = new Uint8Array(),
    footer = new Uint8Array(),
    assertion = new Uint8Array(),
  ) => {
    if (typeof key !== 'string') throw new errors.PASERKInvalid('TODO')
    if (!(payload instanceof Uint8Array)) throw new TypeError('TODO')
    if (!(footer instanceof Uint8Array)) throw new TypeError('TODO')
    if (!(assertion instanceof Uint8Array)) throw new TypeError('TODO')

    if (assertion.byteLength && !config[kAssertion])
      throw new TypeError(
        `PASETO protocol v${config[kVersion]} does not support implicit assertions`,
      )

    return config[kSeal](key, payload, footer, assertion)
  }
}

export function unseal(config: VersionPurposeLocal | VersionPurposePublic): UnsealFn {
  return async (key, token: string, assertion = new Uint8Array()) => {
    if (typeof key !== 'string') throw new errors.PASERKInvalid('TODO')

    if (assertion !== undefined) {
      if (!(assertion instanceof Uint8Array)) throw new TypeError('TODO')
      if (assertion.byteLength && !config[kAssertion])
        throw new TypeError(
          `PASETO protocol v${config[kVersion]} does not support implicit assertions`,
        )
    }

    if (typeof token !== 'string') throw new TypeError('TODO')
    if (!token.startsWith(`v${config[kVersion]}.${config[kPurpose]}.`)) throw new Error('TODO')

    let { 0: version, 1: purpose, 2: payload, 3: footer, length } = token.split('.')

    if (footer && length !== 4) throw new Error('TODO')
    if (!footer && length !== 3) throw new Error('TODO')
    if (version !== `v${config[kVersion]}`) throw new Error('TODO')
    if (purpose !== config[kPurpose]) throw new Error('TODO')

    return config[kUnseal](
      key,
      base64url.decode(payload),
      footer ? base64url.decode(footer) : new Uint8Array(),
      assertion,
    )
  }
}

export function v1() {
  return {
    sign: seal(V1Public),
    verify: unseal(V1Public),
    encrypt: seal(V1Local),
    decrypt: unseal(V1Local),
    generateSecret: generate(V1Local),
    generateKeyPair: generate(V1Public),
  }
}

export function v2() {
  return {
    sign: seal(V2Public),
    verify: unseal(V2Public),
    encrypt: seal(V2Local),
    decrypt: unseal(V2Local),
    generateSecret: generate(V2Local),
    generateKeyPair: generate(V2Public),
  }
}

export function v3() {
  return {
    sign: seal(V3Public),
    verify: unseal(V3Public),
    encrypt: seal(V3Local),
    decrypt: unseal(V3Local),
    generateSecret: generate(V3Local),
    generateKeyPair: generate(V3Public),
  }
}

export function v4() {
  return {
    sign: seal(V4Public),
    verify: unseal(V4Public),
    encrypt: seal(V4Local),
    decrypt: unseal(V4Local),
    generateSecret: generate(V4Local),
    generateKeyPair: generate(V4Public),
  }
}

export { errors }
