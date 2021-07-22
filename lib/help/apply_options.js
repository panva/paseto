const ms = require('../help/ms')

module.exports = (
  { audience, expiresIn, iat = true, issuer, jti, kid, notBefore, now = new Date(), subject },
  payload,
) => {
  if (!(now instanceof Date) || !now.getTime()) {
    throw new TypeError('options.now must be a valid Date object')
  }

  const unix = now.getTime()

  if (iat !== undefined) {
    if (typeof iat !== 'boolean') {
      throw new TypeError('options.iat must be a boolean')
    }

    if (iat) {
      payload.iat = new Date(unix)
    }
  }

  if (expiresIn !== undefined) {
    if (typeof expiresIn !== 'string') {
      throw new TypeError('options.expiresIn must be a string')
    }

    payload.exp = new Date(unix + ms(expiresIn))
  }

  if (notBefore !== undefined) {
    if (typeof notBefore !== 'string') {
      throw new TypeError('options.notBefore must be a string')
    }

    payload.nbf = new Date(unix + ms(notBefore))
  }

  if (audience !== undefined) {
    if (typeof audience !== 'string') {
      throw new TypeError('options.audience must be a string')
    }

    payload.aud = audience
  }

  if (issuer !== undefined) {
    if (typeof issuer !== 'string') {
      throw new TypeError('options.issuer must be a string')
    }

    payload.iss = issuer
  }

  if (subject !== undefined) {
    if (typeof subject !== 'string') {
      throw new TypeError('options.subject must be a string')
    }

    payload.sub = subject
  }

  if (kid !== undefined) {
    if (typeof kid !== 'string') {
      throw new TypeError('options.kid must be a string')
    }

    payload.kid = kid
  }

  if (jti !== undefined) {
    if (typeof jti !== 'string') {
      throw new TypeError('options.jti must be a string')
    }

    payload.jti = jti
  }

  return payload
}
