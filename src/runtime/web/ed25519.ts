import * as stable from '../../stablelib/ed25519.js'

export function sign(data: Uint8Array, key: Uint8Array) {
  return stable.sign(key, data)
}

export function verify(data: Uint8Array, key: Uint8Array, signature: Uint8Array) {
  try {
    return stable.verify(key, data, signature)
  } catch {
    return false
  }
}
