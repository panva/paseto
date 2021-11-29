import * as crypto from 'crypto'

export default (data: Uint8Array, key: Uint8Array) =>
  crypto.createHmac('sha384', key).update(data).digest()
