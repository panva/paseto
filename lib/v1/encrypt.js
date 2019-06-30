const applyOptions = require('../help/apply_options')
const checkFooter = require('../help/check_footer')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v1.local')
const checkPayload = require('../help/check_payload')
const hkdf = require('../help/hkdf')
const pack = require('../help/pack')
const pae = require('../help/pae')
const randomBytes = require('../help/random_bytes')
const { hmac, encrypt } = require('../help/crypto_worker')

module.exports = async function v1Encrypt (payload, key, { footer, nonce, ...options } = {}) {
  payload = checkPayload(payload)
  key = checkKey(key)
  const f = checkFooter(footer)
  payload = applyOptions(options, payload)

  const m = Buffer.from(JSON.stringify(payload), 'utf8')
  const h = 'v1.local.'
  const k = key.export()

  if ((nonce && process.env.NODE_ENV !== 'test') || !nonce) {
    nonce = await randomBytes(32)
  }

  let n = await hmac('sha384', m, nonce)
  n = n.slice(0, 32)

  const salt = n.slice(0, 16)
  const ek = await hkdf(k, 32, salt, 'paseto-encryption-key')
  const ak = await hkdf(k, 32, salt, 'paseto-auth-key-for-aead')

  const c = await encrypt('aes-256-ctr', m, ek, n.slice(16))
  const preAuth = pae(h, n, c, f)
  const t = await hmac('sha384', preAuth, ak)

  return pack(h, [n, c, t], f)
}
