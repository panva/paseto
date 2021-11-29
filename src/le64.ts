function writeUInt32LE(buf: Uint8Array, value: number, offset: number) {
  buf[offset + 3] = value >>> 24
  buf[offset + 2] = value >>> 16
  buf[offset + 1] = value >>> 8
  buf[offset] = value & 0xff
}

export default (n: number) => {
  if (!Number.isSafeInteger(n)) {
    throw new TypeError('TODO')
  }

  const up = ~~(n / 0xffffffff)
  const dn = (n % 0xffffffff) - up

  const buf = new Uint8Array(8)

  writeUInt32LE(buf, up, 4)
  writeUInt32LE(buf, dn, 0)

  return buf
}
