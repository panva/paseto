import { constants } from 'crypto'

import * as sig from './sig.js'

export async function sign(data: Uint8Array, key: Uint8Array) {
  return sig.sign('sha384', data, {
    key: Buffer.from(key),
    format: 'der',
    type: 'pkcs1',
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
  })
}

export async function verify(data: Uint8Array, key: Uint8Array, signature: Uint8Array) {
  return sig.verify(
    'sha384',
    data,
    {
      key: Buffer.from(key),
      format: 'der',
      type: 'pkcs1',
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
    },
    signature,
  )
}
