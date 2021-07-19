const sign = require('./sign')
const verify = require('./verify')
const { generateKey, bytesToKeyObject, keyObjectToBytes } = require('./key')

module.exports = { sign, verify, generateKey, bytesToKeyObject, keyObjectToBytes }
