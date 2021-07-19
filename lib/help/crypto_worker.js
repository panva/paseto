const crypto = require('crypto')
const util = require('util')

const pae = require('./pae')
const pack = require('./pack')
const { PasetoDecryptionFailed } = require('../errors')
const timingSafeEqual = require('./timing_safe_equal')

const {
  webcrypto: { subtle },
} = crypto
const hkdf = util.promisify(crypto.hkdf)

const EK_INFO = Buffer.from('paseto-encryption-key')
const AK_INFO = Buffer.from('paseto-auth-key-for-aead')
const EMPTY = Buffer.alloc(0)

async function v1encrypt(m, f, k) {
  const h = 'v1.local.'
  const n = hmac(m, crypto.randomBytes(32)).subarray(0, 32)
  const salt = n.subarray(0, 16)
  const [ek, ak] = await Promise.all([
    hkdf('sha384', k, salt, EK_INFO, 32).then(Buffer.from),
    hkdf('sha384', k, salt, AK_INFO, 32).then(Buffer.from),
  ])

  const c = await encrypt(m, ek, n.subarray(16))
  const preAuth = pae(h, n, c, f)
  const t = hmac(preAuth, ak)

  return pack(h, f, n, c, t)
}

async function v1decrypt(raw, f, k) {
  const h = 'v1.local.'
  const n = raw.subarray(0, 32)
  const t = raw.subarray(-48)
  const c = raw.subarray(32, -48)

  const salt = n.subarray(0, 16)
  const [ek, ak] = await Promise.all([
    hkdf('sha384', k, salt, EK_INFO, 32).then(Buffer.from),
    hkdf('sha384', k, salt, AK_INFO, 32).then(Buffer.from),
  ])

  const preAuth = pae(h, n, c, f)

  const t2 = hmac(preAuth, ak)
  if (!timingSafeEqual(t, t2)) throw new PasetoDecryptionFailed('decryption failed')
  const payload = await decrypt(c, ek, n.subarray(16))
  if (!payload) throw new PasetoDecryptionFailed('decryption failed')

  return payload
}

async function v3encrypt(m, f, k, i) {
  const h = 'v3.local.'
  const n = crypto.randomBytes(32)
  const [tmp, ak] = await Promise.all([
    hkdf('sha384', k, EMPTY, Buffer.concat([EK_INFO, n]), 48).then(Buffer.from),
    hkdf('sha384', k, EMPTY, Buffer.concat([AK_INFO, n]), 48).then(Buffer.from),
  ])
  const ek = tmp.subarray(0, 32)
  const n2 = tmp.subarray(32)

  const c = await encrypt(m, ek, n2)
  const preAuth = pae(h, n, c, f, i)
  const t = hmac(preAuth, ak)

  return pack(h, f, n, c, t)
}

async function v3decrypt(raw, f, k, i) {
  const h = 'v3.local.'
  const n = raw.subarray(0, 32)
  const t = raw.subarray(-48)
  const c = raw.subarray(32, -48)

  const [tmp, ak] = await Promise.all([
    hkdf('sha384', k, EMPTY, Buffer.concat([EK_INFO, n]), 48).then(Buffer.from),
    hkdf('sha384', k, EMPTY, Buffer.concat([AK_INFO, n]), 48).then(Buffer.from),
  ])

  const ek = tmp.subarray(0, 32)
  const n2 = tmp.subarray(32)
  const preAuth = pae(h, n, c, f, i)
  const t2 = hmac(preAuth, ak)

  if (!timingSafeEqual(t, t2)) throw new PasetoDecryptionFailed('decryption failed')
  const payload = await decrypt(c, ek, n2)
  if (!payload) throw new PasetoDecryptionFailed('decryption failed')

  return payload
}

const hmac = (data, key) => crypto.createHmac('sha384', key).update(data).digest()

const ctr = async (op, data, key, iv) =>
  subtle[op](
    { name: 'AES-CTR', counter: iv, length: 16 },
    await subtle.importKey('raw', key, 'AES-CTR', false, [op]),
    data,
  ).then(Buffer.from)
const encrypt = ctr.bind(undefined, 'encrypt')
const decrypt = ctr.bind(undefined, 'decrypt')

module.exports = {
  sign: util.promisify(crypto.sign),
  verify: util.promisify(crypto.verify),
  'v1.local-encrypt': v1encrypt,
  'v1.local-decrypt': v1decrypt,
  'v3.local-encrypt': v3encrypt,
  'v3.local-decrypt': v3decrypt,
}
