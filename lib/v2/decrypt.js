const { 'xchacha20-poly1305-decrypt': decrypt } = require('../help/crypto_worker')
const { decode } = require('../help/base64url')
const { PasetoDecryptionFailed, PasetoInvalid } = require('../errors')
const assertPayload = require('../help/assert_payload')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v2.local')
const pae = require('../help/pae')
const parse = require('../help/parse_paseto_payload')

const h = 'v2.local.'

module.exports = async function v2Decrypt (token, key, { complete = false, ...options } = {}) {
  if (typeof token !== 'string') {
    throw new TypeError(`token must be a string, got: ${typeof token}`)
  }

  key = checkKey(key)

  if (token.substr(0, h.length) !== h) {
    throw new PasetoInvalid('token is not a v2.local PASETO')
  }

  const { 0: b64, 1: b64f = '', length } = token.substr(h.length).split('.')
  if (length > 2) {
    throw new PasetoInvalid('token value is not a PASETO formatted value')
  }

  const f = decode(b64f)
  const raw = decode(b64)
  const n = raw.slice(0, 24)
  const c = raw.slice(24)

  const k = key.export()
  const preAuth = pae(h, n, f)
  let payload = await decrypt(c, n, k, preAuth)
  if (!payload) {
    throw new PasetoDecryptionFailed('decryption failed')
  }

  payload = parse(payload)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer: f.length ? f : undefined, version: 'v2', purpose: 'local' }
  }

  return payload
}
