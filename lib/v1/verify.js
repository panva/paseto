const {
  constants: { RSA_PKCS1_PSS_PADDING: padding, RSA_PSS_SALTLEN_DIGEST: saltLength },
  createPublicKey,
} = require('crypto')

const verify = require('../help/verify')
const isKeyObject = require('../help/is_key_object')
const { post } = require('../help/consume')

function checkKey(key) {
  if (typeof key === 'string' && key.startsWith('k1.public.')) {
    try {
      const der = Buffer.from(key.slice(10), 'base64url')
      key = { key: der, format: 'der', type: 'pkcs1' }
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
    key.asymmetricKeyType !== 'rsa' ||
    key.asymmetricKeyDetails.modulusLength !== 2048
  ) {
    throw new TypeError(
      'v1.public verify key must be a public RSA key with 2048 bit modulus length',
    )
  }

  return key
}

module.exports = async function v1Verify(
  token,
  key,
  { complete = false, buffer = false, ...options } = {},
) {
  key = checkKey(key)

  const { m, footer } = await verify('v1.public.', token, 'sha384', 256, {
    key,
    padding,
    saltLength,
  })

  return post('v1', buffer, options, complete, m, footer, 'public')
}
