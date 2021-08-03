const { PasetoInvalid } = require('../errors')

const { strict: assert } = require('assert')
const isObject = require('./is_object')

module.exports = (payload) => {
  try {
    const parsed = JSON.parse(payload)
    assert(isObject(parsed))
    return parsed
  } catch {
    throw new PasetoInvalid('All PASETO payloads MUST be a JSON object')
  }
}
