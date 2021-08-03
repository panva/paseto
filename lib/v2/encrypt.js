const checkFooter = require('../help/check_footer')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v2.local')
const checkPayload = require('../help/check_payload')
const { 'v2.local-encrypt': encrypt } = require('../help/crypto_worker')

module.exports = async function v2Encrypt(payload, key, { footer, ...options } = {}) {
  const m = checkPayload(payload, options)
  key = checkKey(key)
  const f = checkFooter(footer)
  const k = key.export()
  return encrypt(m, f, k)
}
