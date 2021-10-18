const { createPublicKey } = require('crypto')

const test = require('ava')

const { decode, errors, ...lib } = require('../lib')

for (const [version, { sign, verify, encrypt, decrypt, generateKey }] of Object.entries(lib).filter(
  ([key]) => key.startsWith('V'),
)) {
  test(`${version.toLowerCase()}.public.`, async (t) => {
    for (const [pk, sk] of [
      await generateKey('public').then((sk) => [createPublicKey(sk), sk]),
      await generateKey('public', { format: 'paserk' }).then((kp) => [kp.publicKey, kp.secretKey]),
    ]) {
      const footer = 'footer'
      const payload = { foo: 'bar' }
      const signOptions = { footer }
      const verifyOptions = {}
      if (version === 'V3' || version === 'V4') {
        signOptions.assertion = `${version.toLowerCase()}.public.`
        verifyOptions.assertion = signOptions.assertion
      }

      const [token] = await Promise.all([
        sign(payload, sk, { ...signOptions, iat: false }),
        sign(Buffer.from(JSON.stringify(payload)), sk, signOptions),
      ])

      t.deepEqual(decode(token), {
        payload,
        purpose: 'public',
        version: version.toLowerCase(),
        footer: Buffer.from(footer),
      })

      t.deepEqual(await verify(token, pk, { ...verifyOptions }), payload)
      t.deepEqual(await verify(token, pk, { ...verifyOptions, complete: true }), {
        payload,
        purpose: 'public',
        version: version.toLowerCase(),
        footer: Buffer.from(footer),
      })
      t.deepEqual(await verify(token, pk, { ...verifyOptions, complete: true, buffer: true }), {
        payload: Buffer.from(JSON.stringify(payload)),
        purpose: 'public',
        version: version.toLowerCase(),
        footer: Buffer.from(footer),
      })

      if (version === 'V3' || version === 'V4') {
        await t.throwsAsync(verify(token, pk), { code: 'ERR_PASETO_VERIFICATION_FAILED' })
      }

      await t.throwsAsync(verify(token, await generateKey('public')), {
        code: 'ERR_PASETO_VERIFICATION_FAILED',
      })
    }
  })

  if (encrypt) {
    test(`${version.toLowerCase()}.local.`, async (t) => {
      for (const sk of [
        await generateKey('local'),
        await generateKey('local', { format: 'paserk' }),
      ]) {
        const footer = 'footer'
        const payload = { foo: 'bar' }
        const encryptOptions = { footer }
        const decryptOptions = {}
        if (version === 'V3' || version === 'V4') {
          encryptOptions.assertion = `${version.toLowerCase()}.local.`
          decryptOptions.assertion = encryptOptions.assertion
        }

        const [token] = await Promise.all([
          encrypt(payload, sk, { ...encryptOptions, iat: false }),
          encrypt(Buffer.from(JSON.stringify(payload)), sk, encryptOptions),
        ])

        t.deepEqual(decode(token), {
          payload: undefined,
          purpose: 'local',
          version: version.toLowerCase(),
          footer: Buffer.from(footer),
        })

        t.deepEqual(await decrypt(token, sk, { ...decryptOptions }), payload)
        t.deepEqual(await decrypt(token, sk, { ...decryptOptions, complete: true }), {
          payload,
          purpose: 'local',
          version: version.toLowerCase(),
          footer: Buffer.from(footer),
        })
        t.deepEqual(await decrypt(token, sk, { ...decryptOptions, complete: true, buffer: true }), {
          payload: Buffer.from(JSON.stringify(payload)),
          purpose: 'local',
          version: version.toLowerCase(),
          footer: Buffer.from(footer),
        })

        if (version === 'V3' || version === 'V4') {
          await t.throwsAsync(decrypt(token, sk), { code: 'ERR_PASETO_DECRYPTION_FAILED' })
        }

        await t.throwsAsync(decrypt(token, await generateKey('local')), {
          code: 'ERR_PASETO_DECRYPTION_FAILED',
        })
      }
    })
  }
}
