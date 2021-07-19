const { createPublicKey } = require('crypto')

const assertPayload = require('../help/assert_payload')
const parse = require('../help/parse_paseto_payload')
const checkAssertion = require('../help/check_assertion')
const verify = require('../help/verify')
const isKeyObject = require('../help/is_key_object')
const { bytesToKeyObject } = require('./key')

function checkKey(key) {
  if (Buffer.isBuffer(key)) {
    try {
      key = bytesToKeyObject(key)
    } catch {}
  }

  if (!isKeyObject(key) || key.type === 'private') {
    try {
      key = createPublicKey(key)
    } catch {}
  }

  if (!isKeyObject(key)) {
    throw new TypeError('invalid key provided')
  }

  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new TypeError('v4.public verify key must be a public ed25519 key')
  }

  return key
}

module.exports = async function v4Verify(
  token,
  key,
  { complete = false, buffer = false, assertion, ...options } = {},
) {
  key = checkKey(key)
  const i = checkAssertion(assertion)

  const { m, footer } = await verify('v4.public.', token, undefined, 64, key, i)

  if (buffer) {
    if (Object.keys(options).length !== 0) {
      throw new TypeError('options cannot contain claims when options.buffer is true')
    }
    if (complete) {
      return { payload: m, footer, version: 'v4', purpose: 'public' }
    }

    return m
  }

  const payload = parse(m)
  assertPayload(options, payload)

  if (complete) {
    return { payload, footer, version: 'v4', purpose: 'public' }
  }

  return payload
}
