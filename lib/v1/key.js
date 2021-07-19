const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')

const generateKeyPair = promisify(crypto.generateKeyPair)
const generateSecretKey = promisify(crypto.generateKey)

async function generateKey(purpose) {
  switch (purpose) {
    case 'local':
      return generateSecretKey('aes', { length: 256 })
    case 'public': {
      const { privateKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
      return privateKey
    }
    default:
      throw new PasetoNotSupported('unsupported v1 purpose')
  }
}

module.exports = generateKey
