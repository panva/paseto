module.exports = function checkAssertion(assertion) {
  if (typeof assertion === 'undefined') {
    return Buffer.from('')
  }

  if (Buffer.isBuffer(assertion)) {
    return assertion
  }

  if (typeof assertion !== 'string') {
    throw new TypeError('options.assertion must be a string, or a Buffer')
  }

  return Buffer.from(assertion, 'utf8')
}
