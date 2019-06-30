const applyOptions = require('../help/apply_options')
const checkFooter = require('../help/check_footer')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v2.local')
const checkPayload = require('../help/check_payload')
const pack = require('../help/pack')
const randomBytes = require('../help/random_bytes')
const { 'xchacha20-poly1305-encrypt': encrypt } = require('../help/crypto_worker')

module.exports = async function v2Encrypt (payload, key, { footer, nonce, ...options } = {}) {
  payload = checkPayload(payload)
  key = checkKey(key)
  const f = checkFooter(footer)
  payload = applyOptions(options, payload)

  const m = Buffer.from(JSON.stringify(payload), 'utf8')
  const h = 'v2.local.'
  const k = key.export()

  if ((nonce && process.env.NODE_ENV !== 'test') || !nonce) {
    nonce = await randomBytes(32)
  }

  const { n, c } = await encrypt(m, nonce, k, f)

  return pack(h, [n, c], f)
}
