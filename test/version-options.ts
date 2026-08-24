import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as PASETO from '../index.ts'

const key: PASETO.Key = { algorithm: { name: 'test' }, extractable: false, type: 'secret' }
const password = new Uint8Array()

function rejectsUnsupportedOption(error: unknown): boolean {
  return error instanceof TypeError && /does not support/u.test(error.message)
}

for (const version of [1, 2] as const) {
  test(`v${version} rejects an explicitly present implicit assertion before cryptography`, async () => {
    let calls = 0
    const EncryptFactory = PASETO.LocalEncrypt<1 | 2, PASETO.Key>({
      version,
      run: async () => {
        calls++
        return new Uint8Array()
      },
    })
    const DecryptFactory = PASETO.LocalDecrypt<1 | 2, PASETO.Key>({
      version,
      run: async () => {
        calls++
        return new Uint8Array()
      },
    })
    const SignFactory = PASETO.PublicSign<1 | 2, PASETO.Key>({
      version,
      run: async () => {
        calls++
        return new Uint8Array()
      },
    })
    const VerifyFactory = PASETO.PublicVerify<1 | 2, PASETO.Key>({
      version,
      run: async () => {
        calls++
        return true
      },
    })

    for (const implicitAssertion of [undefined, new Uint8Array()]) {
      const options = { implicitAssertion } as never
      await assert.rejects(EncryptFactory().run(key, {}, options), rejectsUnsupportedOption)
      await assert.rejects(
        DecryptFactory().run(key, 'malformed', options),
        rejectsUnsupportedOption,
      )
      await assert.rejects(SignFactory().run(key, {}, options), rejectsUnsupportedOption)
      await assert.rejects(VerifyFactory().run(key, 'malformed', options), rejectsUnsupportedOption)
    }

    assert.equal(calls, 0)
  })
}

for (const version of [1, 2, 3, 4] as const) {
  test(`PASERK v${version} rejects incompatible password options before implementations`, async () => {
    let localWrapCalls = 0
    let localUnwrapCalls = 0
    let publicWrapCalls = 0
    let publicUnwrapCalls = 0

    const LocalWrapFactory = PASETO.LocalWrapKeyWithPassword<PASETO.Version, PASETO.Key>({
      version,
      run: async () => {
        localWrapCalls++
        return `k${version}.local-pw.payload` as PASETO.PasswordWrappedLocalPASERK
      },
    })
    const LocalUnwrapFactory = PASETO.LocalUnwrapKeyWithPassword<PASETO.Version, PASETO.Key>({
      version,
      run: async () => {
        localUnwrapCalls++
        return key
      },
    })
    const PublicWrapFactory = PASETO.PublicWrapSecretKeyWithPassword<PASETO.Version, PASETO.Key>({
      version,
      run: async () => {
        publicWrapCalls++
        return `k${version}.secret-pw.payload` as PASETO.PasswordWrappedSecretPASERK
      },
    })
    const PublicUnwrapFactory = PASETO.PublicUnwrapSecretKeyWithPassword<
      PASETO.Version,
      PASETO.Key
    >({
      version,
      run: async () => {
        publicUnwrapCalls++
        return key
      },
    })

    const wrapOptions =
      version === 1 || version === 3 ? ['memory', 'passes', 'parallelism'] : ['iterations']
    const unwrapOptions =
      version === 1 || version === 3
        ? ['maxMemory', 'maxPasses', 'maxParallelism']
        : ['maxIterations']

    for (const name of wrapOptions) {
      const options = { [name]: undefined } as never
      await assert.rejects(LocalWrapFactory().run(key, password, options), rejectsUnsupportedOption)
      await assert.rejects(
        PublicWrapFactory().run(key, password, options),
        rejectsUnsupportedOption,
      )
    }
    for (const name of unwrapOptions) {
      const options = { [name]: undefined } as never
      await assert.rejects(
        LocalUnwrapFactory().run(
          `k${version}.local-pw.payload` as PASETO.PasswordWrappedLocalPASERK,
          password,
          options,
        ),
        rejectsUnsupportedOption,
      )
      await assert.rejects(
        PublicUnwrapFactory().run(
          `k${version}.secret-pw.payload` as PASETO.PasswordWrappedSecretPASERK,
          password,
          options,
        ),
        rejectsUnsupportedOption,
      )
    }

    assert.equal(localWrapCalls, 0)
    assert.equal(localUnwrapCalls, 0)
    assert.equal(publicWrapCalls, 0)
    assert.equal(publicUnwrapCalls, 0)
  })
}
