const checkFooter = require('../help/check_footer')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v3.local')
const checkPayload = require('../help/check_payload')
const checkAssertion = require('../help/check_assertion')
const { 'v3.local-encrypt': encrypt } = require('../help/crypto_worker')

module.exports = async function v3Encrypt(payload, key, { footer, assertion, ...options } = {}) {
  const m = checkPayload(payload, options)
  key = checkKey(key)
  const f = checkFooter(footer)
  const i = checkAssertion(assertion)
  const k = key.export()
  return encrypt(m, f, k, i)
}
