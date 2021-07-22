const { KeyObject } = require('crypto')
let { isKeyObject } = require('util/types')

if (!isKeyObject) {
  isKeyObject = (obj) => obj != null && obj instanceof KeyObject
}

module.exports = isKeyObject
