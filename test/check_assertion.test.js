const test = require('ava')

const checkAssertion = require('../lib/help/check_assertion')

test('when not a buffer, or a string', (t) => {
  t.throws(() => checkAssertion(1), {
    instanceOf: TypeError,
    message: 'options.assertion must be a string, or a Buffer',
  })
})
