const { createSecretKey, KeyObject } = require('crypto')

module.exports = function checkKey (header, key) {
  if (!(key instanceof KeyObject)) {
    key = createSecretKey(key)
  }

  if (key.type !== 'secret' || key.symmetricKeySize !== 32) {
    throw new TypeError(`${header} secret key must be 32 bytes long symmetric key`)
  }

  return key
}
