const { PasetoInvalid, PasetoVerificationFailed } = require('../errors')

const { decode } = require('./base64url')
const { verify } = require('./crypto_worker')
const pae = require('./pae')
const compressPk = require('./compress_pk')

module.exports = async function verifyPaseto(h, token, alg, sigLength, key, i) {
  if (typeof token !== 'string') {
    throw new TypeError('token must be a string')
  }

  if (token.substr(0, h.length) !== h) {
    throw new PasetoInvalid(`token is not a ${h.slice(0, -1)} token`)
  }

  const { 0: b64ms, 1: b64f, length } = token.substr(h.length).split('.')
  if (length !== 1 && length !== 2) {
    throw new PasetoInvalid('token value is not a PASETO formatted value')
  }

  let f
  let ms

  try {
    ms = decode(b64ms)
    f = decode(b64f || '')
  } catch (err) {
    throw new PasetoInvalid('token value is not a PASETO formatted value')
  }

  const m = ms.subarray(0, -sigLength)
  const s = ms.subarray(-sigLength)
  let m2
  if (h === 'v3.public.') {
    m2 = pae(compressPk(key.key), h, m, f, i)
  } else {
    m2 = pae(h, m, f, i)
  }

  const valid = await verify(alg, m2, key, s)

  if (!valid) {
    throw new PasetoVerificationFailed('invalid signature')
  }

  return {
    m,
    footer: f.length ? f : undefined,
  }
}
