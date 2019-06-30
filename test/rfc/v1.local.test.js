const { createSecretKey } = require('crypto')

const test = require('ava')

const { decode, V1 } = require('../../lib')

test('decrypt A.1.1.1.  Test Vector v1-E-1', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUV' +
                'vn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcj' +
                'd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6go' +
                's8fnfjJO8oKiqQMaiBP_Cqncmqw8'

  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V1.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token, { parse: false }), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('encrypt A.1.1.1.  Test Vector v1-E-1', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUV' +
                'vn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcj' +
                'd_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6go' +
                's8fnfjJO8oKiqQMaiBP_Cqncmqw8'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')

  t.deepEqual(await V1.decrypt(await V1.encrypt(payload, sk, { iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V1.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('decrypt A.1.1.2.  Test Vector v1-E-2', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkR' +
                'GlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m' +
                '3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzk' +
                'Mr1RvfDI8emoPoW83q4Q60_xpHaw'

  const expected = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V1.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('encrypt A.1.1.2.  Test Vector v1-E-2', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkR' +
                'GlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m' +
                '3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzk' +
                'Mr1RvfDI8emoPoW83q4Q60_xpHaw'

  const payload = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')

  t.deepEqual(await V1.decrypt(await V1.encrypt(payload, sk, { iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V1.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('decrypt A.1.1.3.  Test Vector v1-E-3', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c' +
                'v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs' +
                '0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHe' +
                'JUYk4IK_JEdUeo_uFRqAIgHsiGCg'

  const expected = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V1.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('encrypt A.1.1.3.  Test Vector v1-E-3', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c' +
                'v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs' +
                '0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHe' +
                'JUYk4IK_JEdUeo_uFRqAIgHsiGCg'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex')

  t.deepEqual(await V1.decrypt(await V1.encrypt(payload, sk, { iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V1.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('decrypt A.1.1.4.  Test Vector v1-E-4', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb' +
                'pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq' +
                'GNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbH' +
                'XUTWXchFEi0etJ4u6tqgxZSklcec'

  const expected = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }

  t.deepEqual(await V1.decrypt(token, sk, { ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('encrypt A.1.1.4.  Test Vector v1-E-4', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb' +
                'pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq' +
                'GNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbH' +
                'XUTWXchFEi0etJ4u6tqgxZSklcec'

  const payload = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }
  const nonce = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex')

  t.deepEqual(await V1.decrypt(await V1.encrypt(payload, sk, { iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V1.encrypt(payload, sk, { nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: undefined, payload: undefined })
})

test('decrypt A.1.1.5.  Test Vector v1-E-5', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c' +
                'v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs' +
                '0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZ' +
                'EWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA' +
                '2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9'

  const expected = {
    payload: { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo' }), 'utf8'),
    version: 'v1',
    purpose: 'local'
  }

  t.deepEqual(await V1.decrypt(token, sk, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: expected.footer, payload: undefined })
})

test('encrypt A.1.1.5.  Test Vector v1-E-5', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c' +
                'v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs' +
                '0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJZ' +
                'EWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA' +
                '2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9'

  const payload = { data: 'this is a signed message', exp: '2019-01-01T00:00:00+00:00' }
  const footer = JSON.stringify({ kid: 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo' })
  const nonce = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex')

  t.deepEqual(await V1.decrypt(await V1.encrypt(payload, sk, { footer, iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V1.encrypt(payload, sk, { footer, nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: Buffer.from(footer), payload: undefined })
})

test('decrypt A.1.1.6.  Test Vector v1-E-6', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb' +
                'pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq' +
                'GNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9' +
                'v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA' +
                '2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9'

  const expected = {
    payload: { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' },
    footer: Buffer.from(JSON.stringify({ kid: 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo' }), 'utf8'),
    version: 'v1',
    purpose: 'local'
  }

  t.deepEqual(await V1.decrypt(token, sk, { complete: true, ignoreExp: true }), expected)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: expected.footer, payload: undefined })
})

test('encrypt A.1.1.6.  Test Vector v1-E-6', async t => {
  const sk = createSecretKey(Buffer.from('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f', 'hex'))
  const token = 'v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb' +
                'pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq' +
                'GNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9' +
                'v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA' +
                '2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9'

  const payload = { data: 'this is a secret message', exp: '2019-01-01T00:00:00+00:00' }
  const footer = JSON.stringify({ kid: 'UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo' })
  const nonce = Buffer.from('26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2', 'hex')

  t.deepEqual(await V1.decrypt(await V1.encrypt(payload, sk, { footer, iat: false }), sk, { ignoreExp: true }), payload)
  t.deepEqual(await V1.encrypt(payload, sk, { footer, nonce, iat: false }), token)
  t.deepEqual(decode(token), { purpose: 'local', version: 'v1', footer: Buffer.from(footer), payload: undefined })
})
