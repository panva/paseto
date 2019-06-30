const test = require('ava')
const crypto = require('crypto')
const { promisify } = require('util')
const generateKeyPair = promisify(crypto.generateKeyPair)

const { errors, V1, V2 } = require('../lib')

test('V1.sign needs a RSA key', async t => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(
    V1.sign({}, privateKey),
    { instanceOf: TypeError, message: 'v1.public signing key must be a private RSA key' }
  )
})

test('V1.sign needs a private key', async t => {
  const { publicKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
  return t.throwsAsync(
    V1.sign({}, publicKey),
    { instanceOf: TypeError, message: 'v1.public signing key must be a private RSA key' }
  )
})

test('V2.sign needs a ed25519 key', async t => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(
    V2.sign({}, privateKey),
    { instanceOf: TypeError, message: 'v2.public signing key must be a private ed25519 key' }
  )
})

test('V2.sign needs a private key', async t => {
  const { publicKey } = await generateKeyPair('ed25519')
  return t.throwsAsync(
    V2.sign({}, publicKey),
    { instanceOf: TypeError, message: 'v2.public signing key must be a private ed25519 key' }
  )
})

test('V1.verify needs a RSA key', async t => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(
    V1.verify({}, privateKey),
    { instanceOf: TypeError, message: 'v1.public verify key must be a public RSA key' }
  )
})

test('V2.verify needs a ed25519 key', async t => {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-256' })
  return t.throwsAsync(
    V2.verify({}, privateKey),
    { instanceOf: TypeError, message: 'v2.public verify key must be a public ed25519 key' }
  )
})

test('token must be a string', async t => {
  const k = await V2.generateKey('public')
  return t.throwsAsync(
    V2.verify(1, k),
    { instanceOf: TypeError, message: 'token must be a string' }
  )
})

test('token must be a a valid paseto', async t => {
  const k = await V2.generateKey('public')
  return t.throwsAsync(
    V2.verify('v2.public...', k),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token value is not a PASETO formatted value' }
  )
})

test('token must be a a valid paseto (encoding payload)', async t => {
  const k = await V2.generateKey('public')
  return t.throwsAsync(
    V2.verify('v2.public.=', k),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token value is not a PASETO formatted value' }
  )
})

test('token must be a a valid paseto (encoding footer)', async t => {
  const k = await V2.generateKey('public')
  return t.throwsAsync(
    V2.verify('v2.public..=', k),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token value is not a PASETO formatted value' }
  )
})

test('invalid RSA key length for v1.public', async t => {
  const { privateKey } = await generateKeyPair('rsa', { modulusLength: 1024 })
  await t.throwsAsync(
    V1.sign({}, privateKey),
    { instanceOf: TypeError, message: 'invalid v1.public signing key bit length' }
  )
})

test('v1 must validate with the right key', async t => {
  const k = await V1.generateKey('public')
  const k2 = await V1.generateKey('public')

  const token = await V1.sign({}, k)

  return t.throwsAsync(
    V1.verify(token, k2),
    { instanceOf: errors.PasetoVerificationFailed, code: 'ERR_PASETO_VERIFICATION_FAILED', message: 'invalid signature' }
  )
})

test('v2 must validate with the right key', async t => {
  const k = await V2.generateKey('public')
  const k2 = await V2.generateKey('public')

  const token = await V2.sign({}, k)

  return t.throwsAsync(
    V2.verify(token, k2),
    { instanceOf: errors.PasetoVerificationFailed, code: 'ERR_PASETO_VERIFICATION_FAILED', message: 'invalid signature' }
  )
})

test('v2 doesnt validate v1', async t => {
  const k = await V1.generateKey('public')
  const k2 = await V2.generateKey('public')

  const token = await V1.sign({}, k)

  return t.throwsAsync(
    V2.verify(token, k2),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token is not a v2.public token' }
  )
})

test('v1 doesnt validate v2', async t => {
  const k = await V1.generateKey('public')
  const k2 = await V2.generateKey('public')

  const token = await V2.sign({}, k2)

  return t.throwsAsync(
    V1.verify(token, k),
    { instanceOf: errors.PasetoInvalid, code: 'ERR_PASETO_INVALID', message: 'token is not a v1.public token' }
  )
})
