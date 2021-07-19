const errors = require('./errors')
const V1 = require('./v1')
const V2 = require('./v2')
const V3 = require('./v3')
const V4 = require('./v4')

const { decode } = require('./general')

module.exports = { decode, V1, V2, V3, V4, errors }
