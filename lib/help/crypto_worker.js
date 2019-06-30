const { parentPort, Worker, isMainThread } = require('worker_threads')

if (isMainThread) {
  const crypto = require('crypto')

  const tasks = new Map()
  const exportArgs = {
    public: [{ format: 'der', type: 'spki' }],
    private: [{ format: 'der', type: 'pkcs8' }]
  }

  let worker
  let taskId = 0

  const spawn = () => {
    worker = new Worker(__filename)
    worker.on('message', function ({ id, value }) {
      const task = tasks.get(id)
      tasks.delete(id)
      if (tasks.size === 0) {
        worker.unref()
      }
      if (value instanceof Uint8Array) {
        value = Buffer.from(value)
      }
      task(value)
    })
  }

  const a = (method, ...args) => new Promise((resolve) => {
    const id = taskId++
    tasks.set(id, resolve)

    if (worker === undefined) {
      spawn()
    }

    let key

    let keyObject = args[2]

    if (keyObject instanceof crypto.KeyObject) {
      key = {
        key: keyObject.export.apply(keyObject, exportArgs[keyObject.type]),
        ...exportArgs[keyObject.type][0]
      }
    } else if (Buffer.isBuffer(keyObject)) {
      key = keyObject
    } else {
      key = keyObject
      keyObject = key.key
      key.key = keyObject.export.apply(keyObject, exportArgs[keyObject.type])
      Object.assign(key, exportArgs[keyObject.type][0])
    }

    args[2] = key

    worker.ref()
    worker.postMessage({ id, method, args })
  })

  module.exports = {
    sign: a.bind(undefined, 'sign'),
    verify: a.bind(undefined, 'verify'),
    encrypt: a.bind(undefined, 'encrypt'),
    decrypt: a.bind(undefined, 'decrypt'),
    hmac: a.bind(undefined, 'hmac'),
    'xchacha20-poly1305-encrypt': a.bind(undefined, 'xchacha20-poly1305-encrypt'),
    'xchacha20-poly1305-decrypt': a.bind(undefined, 'xchacha20-poly1305-decrypt')
  }
/* c8 ignore next 58 */
} else {
  const crypto = require('crypto')
  const sodium = require('libsodium-wrappers')

  const pae = require('./pae')

  const methods = {
    hmac (alg, payload, ab) {
      const key = Buffer.from(ab)
      const hmac = crypto.createHmac(alg, key)
      hmac.update(payload)
      return hmac.digest()
    },
    verify (alg, payload, { key: ab, ...key }, signature) {
      key.key = Buffer.from(ab)
      return crypto.verify(alg, payload, key, signature)
    },
    sign (alg, payload, { key: ab, ...key }) {
      key.key = Buffer.from(ab)
      return crypto.sign(alg, payload, key)
    },
    encrypt (cipher, cleartext, key, iv) {
      const encryptor = crypto.createCipheriv(cipher, key, iv)
      return Buffer.concat([encryptor.update(cleartext), encryptor.final()])
    },
    decrypt (cipher, ciphertext, key, iv) {
      try {
        const decryptor = crypto.createDecipheriv(cipher, key, iv)
        return Buffer.concat([decryptor.update(ciphertext), decryptor.final()])
      } catch (err) {
        return false
      }
    },
    'xchacha20-poly1305-encrypt' (cleartext, nonce, key, footer) {
      let n = sodium.crypto_generichash(24, cleartext, nonce)
      const preAuth = pae('v2.local.', n, footer)

      return {
        n,
        c: sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cleartext, preAuth, undefined, n, key)
      }
    },
    'xchacha20-poly1305-decrypt' (ciphertext, nonce, key, preAuth) {
      try {
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(undefined, ciphertext, preAuth, nonce, key)
      } catch (err) {
        return false
      }
    }
  }

  sodium.ready.then(() => {
    parentPort.on('message', function ({ id, method, args }) {
      let value = methods[method](...args)
      parentPort.postMessage({ id, value })
    })
  })
}
