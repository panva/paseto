const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')
const isKeyObject = require('../help/is_key_object')

const generateKeyPair = promisify(crypto.generateKeyPair)

async function _generateKey(v, purpose) {
  switch (purpose) {
    case 'public': {
      const { privateKey } = await generateKeyPair('ed25519')
      return privateKey
    }
    default:
      throw new PasetoNotSupported(`unsupported ${v} purpose`)
  }
}

function bytesToKeyObject(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError('bytes must be a Buffer')
  }

  switch (bytes.byteLength) {
    case 64: {
      const keyObject = crypto.createPrivateKey({
        key: Buffer.concat([
          Buffer.from('302e020100300506032b657004220420', 'hex'),
          bytes.subarray(0, 32),
        ]),
        format: 'der',
        type: 'pkcs8',
      })

      if (
        !bytes.subarray(32).equals(Buffer.from(keyObject.export({ format: 'jwk' }).x, 'base64'))
      ) {
        throw new TypeError('invalid byte sequence')
      }

      return keyObject
    }
    case 32:
      return crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes]),
        format: 'der',
        type: 'spki',
      })
    default:
      throw new TypeError('bytes must be 64 bytes (private key), or 32 bytes (public key)')
  }
}

function _keyObjectToBytes(v, keyObject) {
  if (!isKeyObject(keyObject)) {
    throw new TypeError('keyObject must be a KeyObject instance')
  }
  if (keyObject.type === 'secret' || keyObject.asymmetricKeyType !== 'ed25519') {
    throw new TypeError(`${v}.public key must be an Ed25519 key`)
  }
  switch (keyObject.type) {
    case 'public':
      return Buffer.from(keyObject.export({ format: 'jwk' }).x, 'base64')
    case 'private': {
      const { d, x } = keyObject.export({ format: 'jwk' })
      return Buffer.concat([Buffer.from(d, 'base64'), Buffer.from(x, 'base64')])
    }
  }
}

async function generateKey(...args) {
  return _generateKey('v2', ...args)
}

function keyObjectToBytes(...args) {
  return _keyObjectToBytes('v2', ...args)
}

module.exports = {
  _generateKey,
  _keyObjectToBytes,
  bytesToKeyObject,
  generateKey,
  keyObjectToBytes,
}
