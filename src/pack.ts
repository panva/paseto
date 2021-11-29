import { encode } from './runtime/base64url.js'
import concat from './concat.js'

export default (version: number, purpose: string, footer: Uint8Array, ...rest: Uint8Array[]) => {
  let token = `v${version}.${purpose}.${encode(concat(rest))}`
  if (footer.byteLength) {
    token += `.${encode(footer)}`
  }
  return token
}
