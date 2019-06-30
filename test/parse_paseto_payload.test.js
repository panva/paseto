const test = require('ava')

const parse = require('../lib/help/parse_paseto_payload')
const errors = require('../lib/errors')

test('not a valid JSON', t => {
  t.throws(
    () => parse("{''}"),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'All PASETO payloads MUST be a JSON object' }
  )
})

test('top level is not an object', t => {
  ;[1, true, false, null, []].forEach((value) => {
    t.throws(
      () => parse(JSON.stringify),
      { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'All PASETO payloads MUST be a JSON object' }
    )
  })
})
