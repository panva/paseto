const { 'v2.local-decrypt': decrypt } = require('../help/crypto_worker')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v2.local')
const { pre, post } = require('../help/consume')

const h = 'v2.local.'

module.exports = async function v2Decrypt(
  token,
  key,
  { complete = false, buffer = false, ...options } = {},
) {
  const { raw, f } = pre(h, token)
  key = checkKey(key)
  const k = key.export()
  const m = await decrypt(raw, f, k)
  return post('v2', buffer, options, complete, m, f, 'local')
}
