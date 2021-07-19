const test = require('ava')

const { V1, V2, V3, V4, errors } = require('../../lib')

test('V1 generateKey generates local', async (t) => {
  await t.notThrowsAsync(V1.generateKey('local'))
})

test('V1 generateKey generates public', async (t) => {
  await t.notThrowsAsync(V1.generateKey('public'))
})

test('V1 generateKey handles invalid purposes', async (t) => {
  await t.throwsAsync(V1.generateKey('foo'), {
    instanceOf: errors.PasetoNotSupported,
    code: 'ERR_PASETO_NOT_SUPPORTED',
    message: 'unsupported v1 purpose',
  })
})

test('V2 generateKey generates public', async (t) => {
  await t.notThrowsAsync(V2.generateKey('public'))
})

test('V2 generateKey handles invalid purposes', async (t) => {
  await t.throwsAsync(V2.generateKey('foo'), {
    instanceOf: errors.PasetoNotSupported,
    code: 'ERR_PASETO_NOT_SUPPORTED',
    message: 'unsupported v2 purpose',
  })
})

test('V3 generateKey generates local', async (t) => {
  await t.notThrowsAsync(V3.generateKey('local'))
})

test('V3 generateKey generates public', async (t) => {
  await t.notThrowsAsync(V3.generateKey('public'))
})

test('V3 generateKey handles invalid purposes', async (t) => {
  await t.throwsAsync(V3.generateKey('foo'), {
    instanceOf: errors.PasetoNotSupported,
    code: 'ERR_PASETO_NOT_SUPPORTED',
    message: 'unsupported v3 purpose',
  })
})

test('V4 generateKey generates public', async (t) => {
  await t.notThrowsAsync(V4.generateKey('public'))
})

test('V4 generateKey handles invalid purposes', async (t) => {
  await t.throwsAsync(V4.generateKey('foo'), {
    instanceOf: errors.PasetoNotSupported,
    code: 'ERR_PASETO_NOT_SUPPORTED',
    message: 'unsupported v4 purpose',
  })
})
