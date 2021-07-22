const {
  constants: {
    RSA_PKCS1_PSS_PADDING: padding,
    RSA_PSS_SALTLEN_DIGEST: saltLength
  },
  createPublicKey,
  KeyObject
} = require('crypto')

const assertPayload = require('../help/assert_payload')
const parse = require('../help/parse_paseto_payload')
const verify = require('../help/verify')

function checkKey (key) {
  if (!(key instanceof KeyObject) || key.type === 'private') {
    key = createPublicKey(key)
  }

  if (key.type !== 'public' || key.asymmetricKeyType !== 'rsa') {
    throw new TypeError('v1.public verify key must be a public RSA key')
  }

  return key
}

module.exports = async function v1Verify (token, key, { complete = false, buffer = false, ...options } = {}) {
  key = checkKey(key)

  const { m, footer } = await verify('v1.public.', token, 'sha384', 256, { key, padding, saltLength })

  if (buffer) {
    if (Object.keys(options).length !== 0) {
      throw new TypeError('options cannot contain claims when options.buffer is true')
    }
    if (complete) {
      return { payload: m, footer, version: 'v1', purpose: 'public' }
    }

    return m
  }

  const payload = parse(m)
  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v1', purpose: 'public' }
  }

  return payload
}
