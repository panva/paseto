const { createPublicKey } = require('crypto')

const checkAssertion = require('../help/check_assertion')
const verify = require('../help/verify')
const isKeyObject = require('../help/is_key_object')
const { bytesToKeyObject } = require('./key')
const compressPk = require('../help/compress_pk')
const { post } = require('../help/consume')

function checkKey(key) {
  if (typeof key === 'string' && key.startsWith('k3.public.')) {
    try {
      key = Buffer.from(key.slice(10), 'base64url')
      assert.strictEqual(key.byteLength, 49)
    } catch {}
  }

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

  if (
    key.type !== 'public' ||
    key.asymmetricKeyType !== 'ec' ||
    key.asymmetricKeyDetails.namedCurve !== 'secp384r1'
  ) {
    throw new TypeError('v3.public verify key must be a public EC P-384 key')
  }

  return key
}

module.exports = async function v3Verify(
  token,
  key,
  { complete = false, buffer = false, assertion, ...options } = {},
) {
  key = checkKey(key)
  const i = checkAssertion(assertion)

  const { m, footer } = await verify(
    'v3.public.',
    token,
    'sha384',
    96,
    { key, dsaEncoding: 'ieee-p1363' },
    i,
    compressPk(key),
  )

  return post('v3', buffer, options, complete, m, footer, 'public')
}
