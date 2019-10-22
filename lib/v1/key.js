const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')
const randomBytes = require('../help/random_bytes')

const generateKeyPair = promisify(crypto.generateKeyPair)

const LOCAL_KEY_LENGTH = 32
const PUBLIC_KEY_ARGS = ['rsa', { modulusLength: 2048 }]

async function generateKey (purpose) {
  switch (purpose) {
    case 'local':
      return crypto.createSecretKey(await randomBytes(LOCAL_KEY_LENGTH))
    case 'public': {
      const { privateKey } = await generateKeyPair(...PUBLIC_KEY_ARGS)
      return privateKey
    }
    default:
      throw new PasetoNotSupported('unsupported v1 purpose')
  }
}

module.exports = generateKey
