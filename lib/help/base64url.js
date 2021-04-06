if (Buffer.isEncoding('base64url')) {
  module.exports.encode = (input) => Buffer.from(input).toString('base64url')
} else {
  module.exports.encode = (input) =>
    input.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

module.exports.decode = (input) => Buffer.from(input, 'base64')
