const {
  createPublicKey,
  KeyObject
} = require('crypto')

const assertPayload = require('../help/assert_payload')
const verify = require('../help/verify')

function checkKey (key) {
  if (!(key instanceof KeyObject) || key.type === 'private') {
    key = createPublicKey(key)
  }

  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('v2.public verify key must be a public ed25519 key')
  }

  return key
}

module.exports = async function v2Verify (token, key, { complete = false, ...options } = {}) {
  key = checkKey(key)

  const { payload, footer } = await verify('v2.public.', token, undefined, 64, key)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v2', purpose: 'public' }
  }

  return payload
}
