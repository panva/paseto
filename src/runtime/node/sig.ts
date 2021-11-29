import * as crypto from 'crypto'
import { promisify } from 'util'

let oneShotSign: (
  alg: string | undefined,
  data: Uint8Array,
  key: Parameters<typeof crypto.sign>[2],
) => Promise<Uint8Array> | Uint8Array
if (crypto.sign.length > 3) {
  oneShotSign = promisify(crypto.sign)
} else {
  oneShotSign = crypto.sign
}

export async function sign(...args: Parameters<typeof oneShotSign>) {
  return oneShotSign(...args)
}

const [major, minor] = process.version
  .substr(1)
  .split('.')
  .map((str) => parseInt(str, 10))

let oneShotVerify: (
  alg: string | undefined,
  data: Uint8Array,
  key: Parameters<typeof crypto.verify>[2],
  signature: Uint8Array,
) => Promise<boolean> | boolean
if (major >= 16 || (major === 15 && minor >= 13)) {
  oneShotVerify = promisify(crypto.verify)
} else {
  oneShotVerify = crypto.verify
}

export async function verify(...args: Parameters<typeof oneShotVerify>) {
  try {
    return await oneShotVerify(...args)
  } catch {
    return false
  }
}
