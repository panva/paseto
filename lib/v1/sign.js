const {
  constants: { RSA_PKCS1_PSS_PADDING: padding, RSA_PSS_SALTLEN_DIGEST: saltLength },
  createPrivateKey,
} = require('crypto')

const checkFooter = require('../help/check_footer')
const checkPayload = require('../help/check_payload')
const sign = require('../help/sign')
const isKeyObject = require('../help/is_key_object')

function checkKey(key) {
  if (typeof key === 'string' && key.startsWith('k1.secret.')) {
    try {
      const der = Buffer.from(key.slice(10), 'base64url')
      key = { key: der, format: 'der', type: 'pkcs1' }
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
    key.asymmetricKeyType !== 'rsa' ||
    key.asymmetricKeyDetails.modulusLength !== 2048
  ) {
    throw new TypeError(
      'v1.public signing key must be a private RSA key with 2048 bit modulus length',
    )
  }

  return key
}

module.exports = async function v1Sign(payload, key, { footer, ...options } = {}) {
  const m = checkPayload(payload, options)
  const f = checkFooter(footer)
  key = checkKey(key)
  return sign('v1.public.', m, f, 'sha384', { key, padding, saltLength })
}
