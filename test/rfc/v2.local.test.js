const { createSecretKey } = require('crypto')

const test = require('ava')

const { decode, V2 } = require('../../lib')

test('decrypt A.2.1.1.  Test Vector v2-E-1', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4Pn' +
                'W8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVOD' +
                'yfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ'

  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V2.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('encrypt A.2.1.1.  Test Vector v2-E-1', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4Pn' +
                'W8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVOD' +
                'yfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('000000000000000000000000000000000000000000000000', 'hex')

  t.deepEqual(await V2.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('decrypt A.2.1.2.  Test Vector v2-E-2', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg' +
                '3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7' +
                'J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w'

  const expected = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V2.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('encrypt A.2.1.2.  Test Vector v2-E-2', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg' +
                '3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7' +
                'J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w'

  const payload = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('000000000000000000000000000000000000000000000000', 'hex')

  t.deepEqual(await V2.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('decrypt A.2.1.3.  Test Vector v2-E-3', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb' +
                'jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6' +
                'Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA'

  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V2.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('encrypt A.2.1.3.  Test Vector v2-E-3', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb' +
                'jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6' +
                'Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex')

  t.deepEqual(await V2.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('decrypt A.2.1.4.  Test Vector v2-E-4', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7' +
                'cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr' +
                'Iu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ'

  const expected = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V2.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('encrypt A.2.1.4.  Test Vector v2-E-4', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7' +
                'cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr' +
                'Iu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ'

  const payload = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex')

  t.deepEqual(await V2.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: undefined, payload: undefined })
})

test('decrypt A.2.1.5.  Test Vector v2-E-5', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb' +
                'jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6' +
                'Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlm' +
                'UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9'

  const expected = {
    payload: { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' }), 'utf8'),
    version: 'v2',
    purpose: 'local'
  }

  t.deepEqual(await V2.decrypt(token, sk, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: expected.footer, payload: undefined })
})

test('encrypt A.2.1.5.  Test Vector v2-E-5', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb' +
                'jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6' +
                'Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlm' +
                'UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const footer = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' })
  const nonce = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex')

  t.deepEqual(await V2.decrypt(await V2.encrypt(payload, sk, { footer, iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V2.encrypt(payload, sk, { footer, nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: Buffer.from(footer), payload: undefined })
})

test('decrypt A.2.1.6.  Test Vector v2-E-6', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7' +
                'cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr' +
                'Iu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlm' +
                'UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9'

  const expected = {
    payload: { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' }), 'utf8'),
    version: 'v2',
    purpose: 'local'
  }

  t.deepEqual(await V2.decrypt(token, sk, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: expected.footer, payload: undefined })
})

test('encrypt A.2.1.6.  Test Vector v2-E-6', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7' +
                'cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr' +
                'Iu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlm' +
                'UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9'

  const payload = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }
  const footer = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' })
  const nonce = Buffer.from('45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b', 'hex')

  t.deepEqual(await V2.decrypt(await V2.encrypt(payload, sk, { footer, iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V2.encrypt(payload, sk, { footer, nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v2', footer: Buffer.from(footer), payload: undefined })
})
