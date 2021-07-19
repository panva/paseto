const test = require('ava')

const applyOptions = require('../lib/help/apply_options')

test('options.iat must be a boolean', (t) => {
  t.throws(() => applyOptions({ iat: 1 }, {}), {
    instanceOf: TypeError,
    message: 'options.iat must be a boolean',
  })
})

test('now not a Date object', (t) => {
  t.throws(() => applyOptions({ now: 1 }, {}), {
    instanceOf: TypeError,
    message: 'options.now must be a valid Date object',
  })
})

test('now not a valid Date object', (t) => {
  t.throws(() => applyOptions({ now: 'foo' }, {}), {
    instanceOf: TypeError,
    message: 'options.now must be a valid Date object',
  })
})
;['expiresIn', 'notBefore', 'audience', 'issuer', 'subject', 'kid', 'jti'].forEach((option) => {
  test(`options.${option} must be a string`, (t) => {
    t.throws(() => applyOptions({ [option]: 1 }, {}), {
      instanceOf: TypeError,
      message: `options.${option} must be a string`,
    })
  })
})

Object.entries({
  issuer: 'iss',
  audience: 'aud',
  kid: 'kid',
  jti: 'jti',
  subject: 'sub',
}).forEach(([option, claim]) => {
  test(`options.${option} puts a ${claim} in the payload`, (t) => {
    t.deepEqual(applyOptions({ [option]: 'value', iat: false }, {}), { [claim]: 'value' })
  })
})

test('defaults', (t) => {
  t.true('iat' in applyOptions({}, {}))
})

test('expiresIn', (t) => {
  t.true('exp' in applyOptions({ expiresIn: '1d' }, {}))
})

test('notBefore', (t) => {
  t.true('nbf' in applyOptions({ notBefore: '1d' }, {}))
})
