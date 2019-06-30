const errors = require('./errors')
const V1 = require('./v1')
const V2 = require('./v2')

const { decode } = require('./general')

module.exports = { decode, V1, V2, errors }
