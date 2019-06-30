const { decode } = require('../help/base64url')
const { hmac, decrypt } = require('../help/crypto_worker')
const { PasetoDecryptionFailed, PasetoInvalid } = require('../errors')
const assertPayload = require('../help/assert_payload')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v1.local')
const hkdf = require('../help/hkdf')
const pae = require('../help/pae')
const parse = require('../help/parse_paseto_payload')
const timingSafeEqual = require('../help/timing_safe_equal')

const h = 'v1.local.'

module.exports = async function v1Decrypt (token, key, { complete = false, ...options } = {}) {
  if (typeof token !== 'string') {
    throw new TypeError(`token must be a string, got: ${typeof token}`)
  }

  key = checkKey(key)

  if (token.substr(0, h.length) !== h) {
    throw new PasetoInvalid('token is not a v1.local PASETO')
  }

  const { 0: b64, 1: b64f = '', length } = token.substr(h.length).split('.')
  if (length > 2) {
    throw new PasetoInvalid('token value is not a PASETO formatted value')
  }

  const f = decode(b64f)
  const raw = decode(b64)
  const n = raw.slice(0, 32)
  const t = raw.slice(-48)
  const c = raw.slice(32, -48)

  const k = key.export()
  const salt = n.slice(0, 16)
  const ek = await hkdf(k, 32, salt, 'paseto-encryption-key')
  const ak = await hkdf(k, 32, salt, 'paseto-auth-key-for-aead')

  const preAuth = pae(h, n, c, f)
  const t2 = await hmac('sha384', preAuth, ak)

  let payload = await decrypt('aes-256-ctr', c, ek, n.slice(16))
  if (!timingSafeEqual(t, t2) || !payload) {
    throw new PasetoDecryptionFailed('decryption failed')
  }

  payload = parse(payload)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer: f.length ? f : undefined, version: 'v1', purpose: 'local' }
  }

  return payload
}
