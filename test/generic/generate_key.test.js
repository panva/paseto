const test = require('ava')

const { V1, V2, errors } = require('../../lib')

test('V1 generateKey generates local', async t => {
  await t.notThrowsAsync(V1.generateKey('local'))
})

test('V1 generateKey generates public', async t => {
  await t.notThrowsAsync(V1.generateKey('public'))
})

test('V1 generateKey handles invalid purposes', async t => {
  await t.throwsAsync(
    V1.generateKey('foo'),
    { instanceOf: errors.PasetoNotSupported, code: 'ERR_PASETO_NOT_SUPPORTED', message: 'unsupported v1 purpose' }
  )
})

test('V2 generateKey generates local', async t => {
  await t.notThrowsAsync(V2.generateKey('local'))
})

test('V2 generateKey generates public', async t => {
  await t.notThrowsAsync(V2.generateKey('public'))
})

test('V2 generateKey handles invalid purposes', async t => {
  await t.throwsAsync(
    V2.generateKey('foo'),
    { instanceOf: errors.PasetoNotSupported, code: 'ERR_PASETO_NOT_SUPPORTED', message: 'unsupported v2 purpose' }
  )
})
