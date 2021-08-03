const { PasetoInvalid, PasetoNotSupported } = require('../errors')
const { decode } = require('../help/base64url')
const parsePayload = require('../help/parse_paseto_payload')

module.exports = (token, /* second arg is private API */ { parse = true } = {}) => {
  if (typeof token !== 'string') {
    throw new TypeError('token must be a string')
  }

  const { 0: version, 1: purpose, 2: payload, 3: footer, length } = token.split('.')

  if (length !== 3 && length !== 4) {
    throw new PasetoInvalid('token is not a PASETO formatted value')
  }

  if (version !== 'v1' && version !== 'v2' && version !== 'v3' && version !== 'v4') {
    throw new PasetoNotSupported('unsupported PASETO version')
  }

  if (purpose !== 'local' && purpose !== 'public') {
    throw new PasetoNotSupported('unsupported PASETO purpose')
  }

  const result = {
    footer: footer ? decode(footer) : undefined,
    payload: undefined,
    version,
    purpose,
  }

  if (purpose === 'local') {
    return result
  }

  const sigLength = version === 'v1' ? 256 : version === 'v3' ? 96 : 64

  let raw
  try {
    raw = decode(payload).subarray(0, -sigLength)
  } catch {
    throw new PasetoInvalid('token is not a PASETO formatted value')
  }

  if (!parse) {
    result.payload = raw
  } else {
    result.payload = parsePayload(raw)
  }

  return result
}
