const b64uRegExp = /^[a-zA-Z0-9_-]*$/

const fromBase64 = (base64) => {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

const toBase64 = (base64url) => {
  return base64url.replace(/-/g, '+').replace(/_/g, '/')
}

const encode = (buf) => {
  return fromBase64(buf.toString('base64'))
}

const decode = (input) => {
  if (!b64uRegExp.test(input)) {
    throw new TypeError('input is not a valid base64url encoded string')
  }
  return Buffer.from(toBase64(input), 'base64')
}

module.exports.decode = decode
module.exports.encode = encode
