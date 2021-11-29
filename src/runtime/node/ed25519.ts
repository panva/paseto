import * as sig from './sig.js'

export async function sign(data: Uint8Array, key: Uint8Array) {
  return sig.sign(undefined, data, {
    key: Buffer.concat([
      new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
      ]),
      key.subarray(0, 32),
    ]),
    format: 'der',
    type: 'pkcs8',
  })
}

export async function verify(data: Uint8Array, key: Uint8Array, signature: Uint8Array) {
  return sig.verify(
    undefined,
    data,
    {
      key: Buffer.concat([
        new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
        key,
      ]),
      format: 'der',
      type: 'spki',
    },
    signature,
  )
}
