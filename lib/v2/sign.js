const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const sign = require('../help/sign')
const { _checkPrivateKey } = require('./key')

const checkKey = _checkPrivateKey.bind(undefined, 'v2')

module.exports = async function v2Sign(payload, key, { footer, ...options } = {}) {
  const m = checkPayload(payload, options)
  key = checkKey(key)
  const f = checkFooter(footer)
  return sign('v2.public.', m, f, undefined, key)
}
