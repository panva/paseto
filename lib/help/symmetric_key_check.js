const { createSecretKey } = require('crypto')

const isKeyObject = require('./is_key_object')

module.exports = function checkKey(header, key) {
  if (!isKeyObject(key)) {
    try {
      key = createSecretKey(key)
    } catch {}
  }

  if (!isKeyObject(key)) {
    throw new TypeError('invalid key provided')
  }

  if (key.type !== 'secret' || key.symmetricKeySize !== 32) {
    throw new TypeError(`${header} secret key must be 32 bytes long symmetric key`)
  }

  return key
}
