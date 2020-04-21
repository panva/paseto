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
  return Buffer.from(toBase64(input), 'base64')
}

module.exports.decode = decode
module.exports.encode = encode
