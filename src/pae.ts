import le64 from './le64.js'

export default (...pieces: Uint8Array[]) => {
  const pae = new Uint8Array(
    8 + pieces.length * 8 + pieces.reduce((acc, { byteLength }) => acc + byteLength, 0),
  )
  let offset = 0
  pae.set(le64(pieces.length), offset)
  offset += 8
  for (let piece of pieces) {
    pae.set(le64(piece.byteLength), offset)
    offset += 8
    pae.set(piece, offset)
    offset += piece.byteLength
  }
  return pae
}
