const crypto = require('crypto')
const { promisify } = require('util')

const randomFill = promisify(crypto.randomFill)

module.exports = async function randomBytes (bytes) {
  const buf = Buffer.allocUnsafe(bytes)
  return randomFill(buf)
}
