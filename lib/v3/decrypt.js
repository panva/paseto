const { decode } = require('../help/base64url')
const { 'v3.local-decrypt': decrypt } = require('../help/crypto_worker')
const { PasetoInvalid } = require('../errors')
const assertPayload = require('../help/assert_payload')
const checkKey = require('../help/symmetric_key_check').bind(undefined, 'v3.local')
const checkAssertion = require('../help/check_assertion')
const parse = require('../help/parse_paseto_payload')

const h = 'v3.local.'

module.exports = async function v3Decrypt(
  token,
  key,
  { complete = false, buffer = false, assertion, ...options } = {},
) {
  if (typeof token !== 'string') {
    throw new TypeError(`token must be a string, got: ${typeof token}`)
  }

  key = checkKey(key)
  const i = checkAssertion(assertion)

  if (token.substr(0, h.length) !== h) {
    throw new PasetoInvalid('token is not a v3.local PASETO')
  }

  const { 0: b64, 1: b64f = '', length } = token.substr(h.length).split('.')
  if (length > 2) {
    throw new PasetoInvalid('token value is not a PASETO formatted value')
  }

  const f = decode(b64f)
  const raw = decode(b64)
  const k = key.export()

  const m = await decrypt(raw, f, k, i)

  if (buffer) {
    if (Object.keys(options).length !== 0) {
      throw new TypeError('options cannot contain claims when options.buffer is true')
    }
    if (complete) {
      return { payload: m, footer: f.length ? f : undefined, version: 'v3', purpose: 'local' }
    }

    return m
  }

  const payload = parse(m)

  assertPayload(options, payload)

  if (complete) {
    return { payload, footer: f.length ? f : undefined, version: 'v3', purpose: 'local' }
  }

  return payload
}
