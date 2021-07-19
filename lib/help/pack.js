const { encode } = require('./base64url')

module.exports = function pack(header, footer, ...payload) {
  let token = `${header}${encode(Buffer.concat(payload))}`
  if (footer.byteLength) {
    token += `.${encode(footer)}`
  }
  return token
}
