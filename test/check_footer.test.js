const test = require('ava')

const checkFooter = require('../lib/help/check_footer')

test('when not a buffer, string or an object', (t) => {
  t.throws(() => checkFooter(1), {
    instanceOf: TypeError,
    message: 'options.footer must be a string, Buffer, or a plain object',
  })
})
