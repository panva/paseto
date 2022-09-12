const test = require('ava')

const {
  V4: { sign, verify, generateKey },
} = require('../lib')

test('https://github.com/panva/paseto/issues/33', async (t) => {
  await t.notThrowsAsync(async () => {
    const key = await generateKey('public', { format: 'paserk' })
    const token = await sign({}, key.secretKey)
    await verify(token, key.publicKey, { complete: true })
  })
})
