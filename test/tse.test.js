const test = require('ava')

const TSE = require('../lib/help/timing_safe_equal')

test('handles different length inputs', t => {
  t.false(TSE(Buffer.from('foo'), Buffer.from('foobar')))
})
