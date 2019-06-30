const { encode } = require('./base64url')

module.exports = function pack (header, payload, footer) {
  if (footer.length !== 0) {
    return `${header}${encode(Buffer.concat(payload))}.${encode(footer)}`
  }

  return `${header}${encode(Buffer.concat(payload))}`
}
