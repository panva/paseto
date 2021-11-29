import * as errors from '../../errors.js'
import * as base64url from './base64url.js'

export async function eoFromSk(key: Uint8Array) {
  const pkcs8 = new Uint8Array(80)
  pkcs8.set(
    new Uint8Array([
      0x30, 0x4e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x37, 0x30, 0x35, 0x02, 0x01, 0x01,
      0x04, 0x30,
    ]),
  )
  pkcs8.set(key, 32)
  // @deno-expect-error
  const k = await crypto.subtle
    .importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign'])
    .catch(() => {
      throw new errors.PASERKInvalid()
    })

  const { x, y } = await crypto.subtle.exportKey('jwk', k)
  const yB = base64url.decode(y!)
  return new Uint8Array([0x02 + (yB[yB.byteLength - 1] & 1), ...base64url.decode(x!)])
}

export async function sign(data: Uint8Array, key: Uint8Array) {
  const pkcs8 = new Uint8Array(80)
  pkcs8.set(
    new Uint8Array([
      0x30, 0x4e, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x37, 0x30, 0x35, 0x02, 0x01, 0x01,
      0x04, 0x30,
    ]),
  )
  pkcs8.set(key, 32)
  // @deno-expect-error
  const k = await crypto.subtle
    .importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['sign'])
    .catch(() => {
      throw new errors.PASERKInvalid()
    })
  const ab = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-384',
    },
    k,
    data,
  )
  return new Uint8Array(ab)
}

export async function verify(data: Uint8Array, key: Uint8Array, signature: Uint8Array) {
  // @deno-expect-error
  const k = await crypto.subtle
    .importKey('raw', key, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify'])
    .catch(() => {
      throw new errors.PASERKInvalid()
    })
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, k, signature, data)
}
