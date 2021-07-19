const applyOptions = require('./apply_options')
const isObject = require('./is_object')
const deepClone = (payload) => JSON.parse(JSON.stringify(payload))

module.exports = (payload, options) => {
  if (Buffer.isBuffer(payload)) {
    if (Object.keys(options).length !== 0) {
      throw new TypeError('options cannot contain claims when payload is a Buffer')
    }

    return payload
  }
  if (!isObject(payload)) {
    throw new TypeError('payload must be a Buffer or a plain object')
  }

  payload = deepClone(payload)
  payload = applyOptions(options, payload)
  return Buffer.from(JSON.stringify(payload), 'utf-8')
}
