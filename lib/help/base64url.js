module.exports.encode = (input) => Buffer.from(input).toString('base64url')
module.exports.decode = (input) => Buffer.from(input, 'base64')
