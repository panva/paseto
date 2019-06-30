const isObject = require('./is_object')
const deepClone = payload => JSON.parse(JSON.stringify(payload))

module.exports = (payload) => {
  if (!isObject(payload)) {
    throw new TypeError('payload must be a plain object')
  }
  return deepClone(payload)
}
