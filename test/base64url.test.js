const test = require('ava')

const base64url = require('../lib/help/base64url')

test('not base64url', t => {
  t.throws(
    () => base64url.decode('='),
    { instanceOf: TypeError, message: 'input is not a valid base64url encoded string' }
  )

  t.throws(
    () => base64url.decode('/'),
    { instanceOf: TypeError, message: 'input is not a valid base64url encoded string' }
  )

  t.throws(
    () => base64url.decode('+'),
    { instanceOf: TypeError, message: 'input is not a valid base64url encoded string' }
  )
})
