const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')

const generateKeyPair = promisify(crypto.generateKeyPair)
const generateSecretKey = promisify(crypto.generateKey)

async function generateKey(purpose, { format = 'keyobject' } = {}) {
  if (format !== 'keyobject' && format !== 'paserk') throw new TypeError('invalid format')
  switch (purpose) {
    case 'local': {
      const keyobject = await generateSecretKey('aes', { length: 256 })
      if (format === 'paserk') {
        return `k1.local.${keyobject.export().toString('base64url')}`
      }
      return keyobject
    }
    case 'public': {
      const { privateKey, publicKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
      if (format === 'paserk') {
        return {
          secretKey: `k1.secret.${privateKey
            .export({ format: 'der', type: 'pkcs1' })
            .toString('base64url')}`,
          publicKey: `k1.public.${publicKey
            .export({ format: 'der', type: 'pkcs1' })
            .toString('base64url')}`,
        }
      }
      return privateKey
    }
    default:
      throw new PasetoNotSupported('unsupported v1 purpose')
  }
}

module.exports = generateKey
