const test = require('ava')

const { decode, V2 } = require('../../lib')

test('verify A.2.2.1.  Test Vector v2-S-1', async t => {
  const token = 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi' +
                'wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGnt' +
                'Tu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_Dj' +
                'JK2ZXC2SUYuOFM-Q_5Cw'
  const pem = '-----BEGIN PUBLIC KEY-----\n' +
              'MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n' +
              '-----END PUBLIC KEY-----'
  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V2.verify(token, pem, { ignoreExp: true }), expected)
})

test('sign A.2.2.1.  Test Vector v2-S-1', async t => {
  const token = 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi' +
                'wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGnt' +
                'Tu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_Dj' +
                'JK2ZXC2SUYuOFM-Q_5Cw'
  const pem = '-----BEGIN PRIVATE KEY-----\n' +
              'MC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n' +
              '-----END PRIVATE KEY-----'
  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V2.sign(payload, pem, { iat: false }), token)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'public', version: 'v2', footer: undefined, payload: Buffer.from(JSON.stringify(payload)) })
})

test('verify A.2.2.2.  Test Vector v2-S-2', async t => {
  const token = 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi' +
                'wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYC' +
                'R0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601' +
                'tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q' +
                '3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9'
  const pem = '-----BEGIN PUBLIC KEY-----\n' +
              'MCowBQYDK2VwAyEAHrnbu7wEfAP9cGBOAHHwmH4Wsot1ciXBHwBBXQ4gsaI=\n' +
              '-----END PUBLIC KEY-----'
  const expected = {
    payload: { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' }), 'utf8'),
    version: 'v2',
    purpose: 'public'
  }

  t.deepEqual(await V2.verify(token, pem, { complete: true, ignoreExp: true }), expected)
})

test('sign A.2.2.2.  Test Vector v2-S-2', async t => {
  const token = 'v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi' +
                'wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYC' +
                'R0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601' +
                'tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q' +
                '3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9'
  const pem = '-----BEGIN PRIVATE KEY-----\n' +
              'MC4CAQAwBQYDK2VwBCIEILTL+0PfTOIQcn2VPkpxMwf6Gbt9n4UEFDjZ4RuUKjd0\n' +
              '-----END PRIVATE KEY-----'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const footer = JSON.stringify({ kid: 'zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN' })

  t.deepEqual(await V2.sign(payload, pem, { footer, iat: false }), token)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'public', version: 'v2', footer: Buffer.from(footer), payload: Buffer.from(JSON.stringify(payload)) })
})
