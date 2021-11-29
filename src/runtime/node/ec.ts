import * as crypto from 'crypto'
import * as sig from './sig.js'

export function eoFromSk(key: Uint8Array) {
  const { x, y } = crypto
    .createPrivateKey({
      key: Buffer.concat([
        new Uint8Array([0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x30]),
        key,
        new Uint8Array([0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
      ]),
      format: 'der',
      type: 'sec1',
    })
    .export({ format: 'jwk' })

  const yB = Buffer.from(y!, 'base64')
  return Buffer.concat([
    Buffer.alloc(1, 0x02 + (yB[yB.byteLength - 1] & 1)),
    Buffer.from(x!, 'base64'),
  ])
}

export async function sign(data: Uint8Array, key: Uint8Array) {
  return sig.sign('sha384', data, {
    key: Buffer.concat([
      new Uint8Array([0x30, 0x3e, 0x02, 0x01, 0x01, 0x04, 0x30]),
      key,
      new Uint8Array([0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
    ]),
    format: 'der',
    type: 'sec1',
    dsaEncoding: 'ieee-p1363',
  })
}

export async function verify(data: Uint8Array, key: Uint8Array, signature: Uint8Array) {
  return sig.verify(
    'sha384',
    data,
    {
      key: Buffer.concat([
        new Uint8Array([
          0x30, 0x46, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05,
          0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x32, 0x00,
        ]),
        key,
      ]),
      format: 'der',
      type: 'spki',
      dsaEncoding: 'ieee-p1363',
    },
    signature,
  )
}
