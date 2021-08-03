const { 'v4.local-decrypt': decrypt } = require('../help/crypto_worker')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v4.local')
const checkAssertion = require('../help/check_assertion')
const { pre, post } = require('../help/consume')

const h = 'v4.local.'

module.exports = async function v4Decrypt(
  token,
  key,
  { complete = false, buffer = false, assertion, ...options } = {},
) {
  const { raw, f } = pre(h, token)
  key = checkKey(key)
  const i = checkAssertion(assertion)
  const k = key.export()
  const m = await decrypt(raw, f, k, i)
  return post('v4', buffer, options, complete, m, f, 'local')
}
