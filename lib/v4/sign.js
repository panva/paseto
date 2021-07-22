const { createPrivateKey } = require('crypto')

const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const checkAssertion = require('../help/check_assertion')
const sign = require('../help/sign')
const isKeyObject = require('../help/is_key_object')

function checkKey(key) {
  if (!isKeyObject(key)) {
    key = createPrivateKey(key)
  }

  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('v4.public signing key must be a private ed25519 key')
  }

  return key
}

module.exports = async function v4Sign(payload, key, { footer, assertion, ...options } = {}) {
  const m = checkPayload(payload, options)
  const i = checkAssertion(assertion)
  key = checkKey(key)
  const f = checkFooter(footer)
  return sign('v4.public.', m, f, undefined, key, i)
}
