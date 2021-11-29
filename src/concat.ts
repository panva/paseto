export default (buffers: Uint8Array[]): Uint8Array => {
  const size = buffers.reduce((acc, { length }) => acc + length, 0)
  const buf = new Uint8Array(size)
  let i = 0
  buffers.forEach((buffer) => {
    buf.set(buffer, i)
    i += buffer.length
  })
  return buf
}
