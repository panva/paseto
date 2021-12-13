const { createPrivateKey } = require('crypto')

const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const checkAssertion = require('../help/check_assertion')
const sign = require('../help/sign')
const isKeyObject = require('../help/is_key_object')
const { bytesToKeyObject } = require('./key')
const compressPk = require('../help/compress_pk')

function checkKey(key) {
  if (typeof key === 'string' && key.startsWith('k3.secret.')) {
    try {
      key = Buffer.from(key.slice(10), 'base64url')
      assert.strictEqual(key.byteLength, 48)
    } catch {}
  }

  if (Buffer.isBuffer(key)) {
    try {
      key = bytesToKeyObject(key)
    } catch {}
  }

  if (!isKeyObject(key)) {
    try {
      key = createPrivateKey(key)
    } catch {}
  }

  if (!isKeyObject(key)) {
    throw new TypeError('invalid key provided')
  }

  if (
    key.type !== 'private' ||
    key.asymmetricKeyType !== 'ec' ||
    key.asymmetricKeyDetails.namedCurve !== 'secp384r1'
  ) {
    throw new TypeError('v3.public signing key must be a private EC P-384 key')
  }

  return key
}

module.exports = async function v3Sign(payload, key, { footer, assertion, ...options } = {}) {
  const m = checkPayload(payload, options)
  const f = checkFooter(footer)
  const i = checkAssertion(assertion)
  key = checkKey(key)
  return sign('v3.public.', m, f, 'sha384', { key, dsaEncoding: 'ieee-p1363' }, i, compressPk(key))
}
