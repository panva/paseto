const le64 = require('./le64')

module.exports = (...pieces) => {
  pieces = pieces.filter(Boolean)
  let accumulator = le64(pieces.length)
  for (let piece of pieces) {
    piece = Buffer.from(piece, 'utf8')
    const len = le64(Buffer.byteLength(piece))
    accumulator = Buffer.concat([accumulator, len, piece])
  }
  return accumulator
}
