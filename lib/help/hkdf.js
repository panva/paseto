const { hmac } = require('./crypto_worker')

module.exports = async function hkdf (key, length, salt, info) {
  const prk = await hmac('sha384', key, salt)

  const u = Buffer.from(info)

  let t = Buffer.from('')
  let lb = Buffer.from('')
  let i

  for (let bi = 1; Buffer.byteLength(t) < length; ++i) {
    i = Buffer.from(String.fromCharCode(bi))
    const inp = Buffer.concat([lb, u, i])

    lb = await hmac('sha384', inp, prk)
    t = Buffer.concat([t, lb])
  }

  const orm = Buffer.from(t).slice(0, length)
  return orm
}
