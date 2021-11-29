import * as crypto from 'crypto'

export function encrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv)
  return Buffer.concat([cipher.update(data), cipher.final()])
}

export function decrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array) {
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv)
  return Buffer.concat([decipher.update(data), decipher.final()])
}
