const { PasetoNotSupported } = require('../errors')

module.exports = (n) => {
  /* c8 ignore next 3 */
  if (!Number.isSafeInteger(n)) {
    throw new PasetoNotSupported('message is too long for Node.js to safely process')
  }

  const up = ~~(n / 0xFFFFFFFF)
  const dn = (n % 0xFFFFFFFF) - up

  const buf = Buffer.allocUnsafe(8)

  buf.writeUInt32LE(up, 4)
  buf.writeUInt32LE(dn, 0)

  return buf
}
