const crypto = require('crypto')
const { promisify } = require('util')

const { PasetoNotSupported } = require('../errors')
const isKeyObject = require('../help/is_key_object')
const compressPk = require('../help/compress_pk')

const generateKeyPair = promisify(crypto.generateKeyPair)
const generateSecretKey = promisify(crypto.generateKey)

async function generateKey(purpose, { format = 'keyobject' } = {}) {
  if (format !== 'keyobject' && format !== 'paserk') throw new TypeError('invalid format')
  switch (purpose) {
    case 'local': {
      const keyobject = await generateSecretKey('aes', { length: 256 })
      if (format === 'paserk') {
        return `k3.local.${keyobject.export().toString('base64url')}`
      }
      return keyobject
    }
    case 'public': {
      const { privateKey, publicKey } = await generateKeyPair('ec', { namedCurve: 'P-384' })
      if (format === 'paserk') {
        return {
          secretKey: `k3.secret.${keyObjectToBytes(privateKey).toString('base64url')}`,
          publicKey: `k3.public.${keyObjectToBytes(publicKey).toString('base64url')}`,
        }
      }
      return privateKey
    }
    default:
      throw new PasetoNotSupported('unsupported v3 purpose')
  }
}

function bytesToKeyObject(bytes) {
  if (!Buffer.isBuffer(bytes)) {
    throw new TypeError('bytes must be a Buffer')
  }

  switch (bytes.byteLength) {
    case 48:
      return crypto.createPrivateKey({
        key: Buffer.concat([
          Buffer.from('303e0201010430', 'hex'),
          bytes,
          Buffer.from('a00706052b81040022', 'hex'),
        ]),
        format: 'der',
        type: 'sec1',
      })
    case 49:
      if (bytes[0] !== 0x02 && bytes[0] !== 0x03) {
        throw new TypeError('invalid compressed public key')
      }
      return crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('3046301006072a8648ce3d020106052b81040022033200', 'hex'),
          bytes,
        ]),
        format: 'der',
        type: 'spki',
      })
    case 97:
      if (bytes[0] !== 0x04) {
        throw new TypeError('invalid uncompressed public key')
      }
      return crypto.createPublicKey({
        key: Buffer.concat([
          Buffer.from('3076301006072a8648ce3d020106052b81040022036200', 'hex'),
          bytes,
        ]),
        format: 'der',
        type: 'spki',
      })
    default:
      throw new TypeError(
        'bytes must be 48 bytes (private key), 49 bytes (compressed public key), or 97 bytes (uncompressed public key)',
      )
  }
}

function keyObjectToBytes(keyObject) {
  if (!isKeyObject(keyObject)) {
    throw new TypeError('keyObject must be a KeyObject instance')
  }
  if (
    keyObject.type === 'secret' ||
    keyObject.asymmetricKeyType !== 'ec' ||
    keyObject.asymmetricKeyDetails.namedCurve !== 'secp384r1'
  ) {
    throw new TypeError('v3.public key must be an EC P-384 key')
  }
  switch (keyObject.type) {
    case 'public':
      return compressPk(keyObject)
    case 'private':
      return Buffer.from(keyObject.export({ format: 'jwk' }).d, 'base64')
  }
}

module.exports = {
  generateKey,
  bytesToKeyObject,
  keyObjectToBytes,
}
