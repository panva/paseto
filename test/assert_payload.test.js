const test = require('ava')

const ms = require('../lib/help/ms')
const errors = require('../lib/errors')
const assertPayload = require('../lib/help/assert_payload')

test('now not a Date object', t => {
  t.throws(
    () => assertPayload({ now: 1 }, {}),
    { instanceOf: TypeError, message: 'options.now must be a valid Date object' }
  )
})

test('now not a valid Date object', t => {
  t.throws(
    () => assertPayload({ now: 'foo' }, {}),
    { instanceOf: TypeError, message: 'options.now must be a valid Date object' }
  )
})

Object.entries({
  issuer: 'iss',
  audience: 'aud',
  subject: 'sub'
}).forEach(([option, claim]) => {
  test(`options.${option} must be a string`, t => {
    t.throws(
      () => assertPayload({ [option]: 1 }, {}),
      { instanceOf: TypeError, message: `options.${option} must be a string` }
    )
  })

  test(`${option} mismatch`, t => {
    t.throws(
      () => assertPayload({ [option]: 'foo' }, {}),
      { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: `${option} mismatch` }
    )
  })

  test(`${option} passes`, t => {
    t.notThrows(() => assertPayload({ [option]: 'foo' }, { [claim]: 'foo' }))
  })

  test(`payload.${claim} must be a string`, t => {
    t.throws(
      () => assertPayload({}, { [claim]: 1 }),
      { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: `payload.${claim} must be a string` }
    )
  })
})

;['iat', 'exp', 'nbf'].forEach((claim) => {
  test(`payload.${claim} must be a string`, t => {
    t.throws(
      () => assertPayload({}, { [claim]: 1 }),
      { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: `payload.${claim} must be a string` }
    )
  })

  test(`payload.${claim} must be an ISO8601 string`, t => {
    t.throws(
      () => assertPayload({}, { [claim]: 'foo' }),
      { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: `payload.${claim} must be a valid ISO8601 string` }
    )
  })
})

test('iat in the future', t => {
  t.throws(
    () => assertPayload({ }, { iat: new Date(Date.now() + 1000).toISOString() }),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'token issued in the future' }
  )
})

test('iat in the future (ignoreIat)', t => {
  t.notThrows(
    () => assertPayload({ ignoreIat: true }, { iat: new Date(Date.now() + 1000).toISOString() })
  )
})

test('iat in the future (clockTolerance)', t => {
  const now = new Date()
  t.notThrows(
    () => assertPayload({ now, clockTolerance: '1s' }, { iat: new Date(now.getTime() + 1000).toISOString() })
  )
})

test('iat in the future (clockTolerance not enough)', t => {
  const now = new Date()
  t.throws(
    () => assertPayload({ now, clockTolerance: '1s' }, { iat: new Date(now.getTime() + 1001).toISOString() }),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'token issued in the future' }
  )
})

test('iat in the past', t => {
  t.notThrows(
    () => assertPayload({ }, { iat: new Date(Date.now() - 1000).toISOString() })
  )
})

test('iat exactly now', t => {
  const now = new Date()
  t.notThrows(
    () => assertPayload({ now }, { iat: now.toISOString() })
  )
})

test('exp in the past (ignoreExp)', t => {
  t.notThrows(
    () => assertPayload({ ignoreExp: true }, { exp: new Date(Date.now() - 1000).toISOString() })
  )
})

test('exp in the past (clockTolerance)', t => {
  const now = new Date()
  t.notThrows(
    () => assertPayload({ now, clockTolerance: '1s' }, { exp: new Date(now.getTime() - 999).toISOString() })
  )
})

test('exp in the past (clockTolerance not enough)', t => {
  const now = new Date()
  t.throws(
    () => assertPayload({ now, clockTolerance: '1s' }, { exp: new Date(now.getTime() - 1001).toISOString() }),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'token is expired' }
  )
})

test('exp in the future', t => {
  t.notThrows(
    () => assertPayload({ }, { exp: new Date(Date.now() + 1000).toISOString() })
  )
})

test('exp exactly now', t => {
  const now = new Date()
  t.throws(
    () => assertPayload({ now }, { exp: now.toISOString() }),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'token is expired' }
  )
})

test('nbf in the future (ignoreNbf)', t => {
  t.notThrows(
    () => assertPayload({ ignoreNbf: true }, { nbf: new Date(Date.now() + 1000).toISOString() })
  )
})

test('nbf in the future (clockTolerance)', t => {
  const now = new Date()
  t.notThrows(
    () => assertPayload({ now, clockTolerance: '1s' }, { nbf: new Date(now.getTime() + 1000).toISOString() })
  )
})

test('nbf in the future (clockTolerance not enough)', t => {
  const now = new Date()
  t.throws(
    () => assertPayload({ now, clockTolerance: '1s' }, { nbf: new Date(now.getTime() + 1001).toISOString() }),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'token is not active yet' }
  )
})

test('nbf in the past', t => {
  t.notThrows(
    () => assertPayload({ }, { nbf: new Date(Date.now() - 1000).toISOString() })
  )
})

test('nbf exactly now', t => {
  const now = new Date()
  t.notThrows(
    () => assertPayload({ now }, { nbf: now.toISOString() })
  )
})

test('clockTolerance must be a string', t => {
  t.throws(
    () => assertPayload({ clockTolerance: 1 }, {}),
    { instanceOf: TypeError, message: 'options.clockTolerance must be a string' }
  )
})

test('blank payload, defaults', t => {
  assertPayload({}, {})
  t.pass()
})

test('blank payload, maxTokenAge', t => {
  t.throws(
    () => assertPayload({ maxTokenAge: 1 }, {}),
    { instanceOf: TypeError, message: 'options.maxTokenAge must be a string' }
  )
})

test('payload missing iat, maxTokenAge', t => {
  t.throws(
    () => assertPayload({ maxTokenAge: '1d' }, {}),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'missing iat claim' }
  )
})

test('maxTokenAge passed', t => {
  t.notThrows(() => assertPayload({ maxTokenAge: '1d' }, { iat: new Date().toISOString() }))
})

test('maxTokenAge exceeded', t => {
  t.throws(
    () => assertPayload({ maxTokenAge: '59m' }, { iat: new Date(Date.now() - ms('60m')).toISOString() }),
    { instanceOf: errors.PasetoClaimInvalid, code: 'ERR_PASETO_CLAIM_INVALID', message: 'maxTokenAge exceeded' }
  )
})
