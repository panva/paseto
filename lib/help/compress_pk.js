module.exports = (key) => {
  const { x, y } = key.export({ format: 'jwk' })
  const yB = Buffer.from(y, 'base64')
  const sign = 0x02 + (yB[yB.length - 1] & 1)
  return Buffer.concat([Buffer.alloc(1, sign), Buffer.from(x, 'base64')])
}
