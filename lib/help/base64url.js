module.exports.encode = (input) => input.toString('base64url')
module.exports.decode = (input) => Buffer.from(input, 'base64')
