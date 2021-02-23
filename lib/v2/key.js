const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')

const generateKeyPair = promisify(crypto.generateKeyPair)

async function generateKey (purpose) {
  switch (purpose) {
    case 'public': {
      const { privateKey } = await generateKeyPair('ed25519')
      return privateKey
    }
    default:
      throw new PasetoNotSupported('unsupported v2 purpose')
  }
}

module.exports = generateKey
