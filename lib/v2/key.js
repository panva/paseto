const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')
const randomBytes = require('../help/random_bytes')

const generateKeyPair = promisify(crypto.generateKeyPair)

const LOCAL_KEY_LENGTH = 32

async function generateKey (purpose) {
  switch (purpose) {
    case 'local':
      return crypto.createSecretKey(await randomBytes(LOCAL_KEY_LENGTH))
    case 'public': {
      const { privateKey } = await generateKeyPair('ed25519')
      return privateKey
    }
    default:
      throw new PasetoNotSupported('unsupported v2 purpose')
  }
}

module.exports = generateKey
