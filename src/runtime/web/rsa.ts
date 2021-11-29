import { writeUint32BE } from '../../stablelib/binary.js'
import * as errors from '../../errors.js'

const encodeLength = (len: number) => {
  if (len < 128) return new Uint8Array([len])
  const buffer = new Uint8Array(5)
  writeUint32BE(len, buffer, 1)
  let offset = 1
  while (buffer[offset] === 0) offset++
  buffer[offset - 1] = 0x80 | (5 - offset)
  return buffer.slice(offset - 1)
}

export async function sign(data: Uint8Array, key: Uint8Array) {
  const pkcs8 = new Uint8Array(26 + key.byteLength)
  pkcs8.set([0x30])
  pkcs8.set(encodeLength(pkcs8.byteLength - 4), 1)
  pkcs8.set(
    [
      0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
      0x01, 0x05, 0x00, 0x04,
    ],
    4,
  )
  pkcs8.set(encodeLength(key.byteLength), 23)
  pkcs8.set(key, 26)

  const k = await crypto.subtle
    .importKey('pkcs8', pkcs8, { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['sign'])
    .catch(() => {
      throw new errors.PASERKInvalid()
    })
  const ab = await crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      hash: 'SHA-384',
      saltLength: 48,
    },
    k,
    data,
  )
  return new Uint8Array(ab)
}

export async function verify(data: Uint8Array, key: Uint8Array, signature: Uint8Array) {
  const spki = new Uint8Array(294)
  spki.set([
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
  ])
  spki.set(key, 24)
  const k = await crypto.subtle
    .importKey('spki', spki, { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify'])
    .catch(() => {
      throw new errors.PASERKInvalid()
    })

  return crypto.subtle.verify(
    {
      name: 'RSA-PSS',
      hash: 'SHA-384',
      saltLength: 48,
    },
    k,
    signature,
    data,
  )
}
