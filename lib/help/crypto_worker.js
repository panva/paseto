const {
  webcrypto: { subtle },
  ...crypto
} = require('crypto')
const util = require('util')

const pae = require('./pae')
const pack = require('./pack')
const timingSafeEqual = require('./timing_safe_equal')

const hkdf = util.promisify(crypto.hkdf)

const EK_INFO = 'paseto-encryption-key'
const AK_INFO = 'paseto-auth-key-for-aead'

async function v1encrypt(m, f, k, nonce) {
  let n = await hmac(m, nonce)
  n = n.subarray(0, 32)
  f = Buffer.from(f)

  const salt = n.subarray(0, 16)
  const [ek, ak] = await Promise.all([
    hkdf('sha384', k, salt, EK_INFO, 32).then(Buffer.from),
    hkdf('sha384', k, salt, AK_INFO, 32).then(Buffer.from),
  ])

  const c = await encrypt(m, ek, n.subarray(16))
  const preAuth = pae('v1.local.', n, c, f)
  const t = await hmac(preAuth, ak)

  return pack('v1.local.', [n, c, t], f)
}

async function v1decrypt(raw, f, k) {
  const n = raw.subarray(0, 32)
  const t = raw.subarray(-48)
  const c = raw.subarray(32, -48)

  const salt = n.subarray(0, 16)
  const [ek, ak] = await Promise.all([
    hkdf('sha384', k, salt, EK_INFO, 32).then(Buffer.from),
    hkdf('sha384', k, salt, AK_INFO, 32).then(Buffer.from),
  ])

  const preAuth = pae('v1.local.', n, c, f)

  const t2 = await hmac(preAuth, ak)
  if (!timingSafeEqual(t, t2)) return false
  const payload = await decrypt(c, ek, n.subarray(16))
  if (!payload) return false

  return payload
}

async function v3encrypt(m, f, k, n, i) {
  f = Buffer.from(f)

  const [tmp, ak] = await Promise.all([
    hkdf('sha384', k, n, EK_INFO, 48).then(Buffer.from),
    hkdf('sha384', k, n, AK_INFO, 32).then(Buffer.from),
  ])
  const ek = tmp.subarray(0, 32)
  const n2 = tmp.subarray(32)

  const c = await encrypt(m, ek, n2)
  const preAuth = pae('v3.local.', n, c, f, i)
  const t = await hmac(preAuth, ak)

  return pack('v3.local.', [n, c, t], f)
}

async function v3decrypt(raw, f, k, i) {
  const n = raw.subarray(0, 32)
  const t = raw.subarray(-48)
  const c = raw.subarray(32, -48)

  const [tmp, ak] = await Promise.all([
    hkdf('sha384', k, n, EK_INFO, 48).then(Buffer.from),
    hkdf('sha384', k, n, AK_INFO, 32).then(Buffer.from),
  ])

  const ek = tmp.subarray(0, 32)
  const n2 = tmp.subarray(32)

  const preAuth = pae('v3.local.', n, c, f, i)

  const t2 = await hmac(preAuth, ak)

  if (!timingSafeEqual(t, t2)) return false
  const payload = await decrypt(c, ek, n2)
  if (!payload) return false

  return payload
}

async function hmac(data, key) {
  key = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-384' }, false, ['sign'])
  return subtle.sign('HMAC', key, data).then(Buffer.from)
}

async function encrypt(cleartext, key, iv) {
  key = await subtle.importKey('raw', key, 'AES-CTR', false, ['encrypt'])
  return subtle
    .encrypt({ name: 'AES-CTR', counter: iv, length: 16 }, key, cleartext)
    .then(Buffer.from)
}

async function decrypt(ciphertext, key, iv) {
  key = await subtle.importKey('raw', key, 'AES-CTR', false, ['decrypt'])
  return subtle
    .decrypt({ name: 'AES-CTR', counter: iv, length: 16 }, key, ciphertext)
    .then(Buffer.from)
}

module.exports = {
  sign: util.promisify(crypto.sign),
  verify: util.promisify(crypto.verify),
  'v1.local-encrypt': v1encrypt,
  'v1.local-decrypt': v1decrypt,
  'v3.local-encrypt': v3encrypt,
  'v3.local-decrypt': v3decrypt,
}
