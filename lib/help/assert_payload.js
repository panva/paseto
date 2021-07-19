const { PasetoClaimInvalid } = require('../errors')
const ms = require('./ms')

module.exports = (
  {
    ignoreExp,
    ignoreNbf,
    ignoreIat,
    maxTokenAge,
    subject,
    issuer,
    clockTolerance,
    audience,
    now = new Date(),
  },
  payload,
) => {
  if (!(now instanceof Date) || !now.getTime()) {
    throw new TypeError('options.now must be a valid Date object')
  }

  const unix = now.getTime()

  // iss
  if ('iss' in payload && typeof payload.iss !== 'string') {
    throw new PasetoClaimInvalid('payload.iss must be a string')
  }

  if (issuer !== undefined) {
    if (typeof issuer !== 'string') {
      throw new TypeError('options.issuer must be a string')
    }

    if (payload.iss !== issuer) {
      throw new PasetoClaimInvalid('issuer mismatch')
    }
  }

  // sub
  if ('sub' in payload && typeof payload.sub !== 'string') {
    throw new PasetoClaimInvalid('payload.sub must be a string')
  }

  if (subject !== undefined) {
    if (typeof subject !== 'string') {
      throw new TypeError('options.subject must be a string')
    }

    if (payload.sub !== subject) {
      throw new PasetoClaimInvalid('subject mismatch')
    }
  }

  // aud
  if ('aud' in payload && typeof payload.aud !== 'string') {
    throw new PasetoClaimInvalid('payload.aud must be a string')
  }

  if (audience !== undefined) {
    if (typeof audience !== 'string') {
      throw new TypeError('options.audience must be a string')
    }

    if (payload.aud !== audience) {
      throw new PasetoClaimInvalid('audience mismatch')
    }
  }

  if (clockTolerance !== undefined && typeof clockTolerance !== 'string') {
    throw new TypeError('options.clockTolerance must be a string')
  }

  const tolerance = clockTolerance ? ms(clockTolerance) : 0

  // iat
  let iat
  if ('iat' in payload) {
    if (typeof payload.iat !== 'string') {
      throw new PasetoClaimInvalid('payload.iat must be a string')
    }
    iat = new Date(payload.iat).getTime()
    if (!iat) {
      throw new PasetoClaimInvalid('payload.iat must be a valid ISO8601 string')
    }
    if (!ignoreIat) {
      if (iat > unix + tolerance) {
        throw new PasetoClaimInvalid('token issued in the future')
      }
    }
  }

  // nbf
  if ('nbf' in payload) {
    if (typeof payload.nbf !== 'string') {
      throw new PasetoClaimInvalid('payload.nbf must be a string')
    }
    const nbf = new Date(payload.nbf).getTime()
    if (!nbf) {
      throw new PasetoClaimInvalid('payload.nbf must be a valid ISO8601 string')
    }
    if (!ignoreNbf) {
      if (nbf > unix + tolerance) {
        throw new PasetoClaimInvalid('token is not active yet')
      }
    }
  }

  // exp
  if ('exp' in payload) {
    if (typeof payload.exp !== 'string') {
      throw new PasetoClaimInvalid('payload.exp must be a string')
    }
    const exp = new Date(payload.exp).getTime()
    if (!exp) {
      throw new PasetoClaimInvalid('payload.exp must be a valid ISO8601 string')
    }
    if (!ignoreExp) {
      if (exp <= unix - tolerance) {
        throw new PasetoClaimInvalid('token is expired')
      }
    }
  }

  // maxTokenAge
  if (maxTokenAge !== undefined) {
    if (typeof maxTokenAge !== 'string') {
      throw new TypeError('options.maxTokenAge must be a string')
    }

    if (!('iat' in payload)) {
      throw new PasetoClaimInvalid('missing iat claim')
    }

    if (iat + ms(maxTokenAge) < unix + tolerance) {
      throw new PasetoClaimInvalid('maxTokenAge exceeded')
    }
  }
}
