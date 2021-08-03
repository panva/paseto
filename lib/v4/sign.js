const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const checkAssertion = require('../help/check_assertion')
const sign = require('../help/sign')
const { _checkPrivateKey } = require('./key')

const checkKey = _checkPrivateKey.bind(undefined, 'v4')

module.exports = async function v4Sign(payload, key, { footer, assertion, ...options } = {}) {
  const m = checkPayload(payload, options)
  const i = checkAssertion(assertion)
  key = checkKey(key)
  const f = checkFooter(footer)
  return sign('v4.public.', m, f, undefined, key, i)
}
