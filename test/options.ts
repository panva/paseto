import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  LocalDecrypt,
  LocalEncrypt,
  LocalProtocol,
  LocalUnwrapKeyWithPassword,
  LocalWrapKeyWithPassword,
  type Key,
} from '../index.ts'
import { GenerateKeyFactory } from '../v3/local.ts'

const key: Key = { algorithm: { name: 'test' }, extractable: false, type: 'secret' }

const invalidOptions = [null, 0, 'options', false, []] as const

test('all operation options must be objects', async () => {
  const keyProtocol = new LocalProtocol(GenerateKeyFactory)
  for (const options of invalidOptions) {
    await assert.rejects(keyProtocol.GenerateKey(options as never), /"options" must be an object/u)
  }
  await assert.rejects(
    keyProtocol.GenerateKey({ extractable: 'yes' } as never),
    /"extractable" must be a boolean/u,
  )

  const EncryptFactory = LocalEncrypt<3, Key>({
    version: 3,
    async run() {
      return Uint8Array.of(1)
    },
  })
  const encrypt = new LocalProtocol(EncryptFactory)
  for (const options of invalidOptions) {
    await assert.rejects(encrypt.Encrypt(key, {}, options as never), /"options" must be an object/u)
  }

  const DecryptFactory = LocalDecrypt<3, Key>({
    version: 3,
    async run() {
      return new TextEncoder().encode('{"exp":"2999-01-01T00:00:00Z"}')
    },
  })
  const decrypt = new LocalProtocol(DecryptFactory)
  for (const options of invalidOptions) {
    await assert.rejects(
      decrypt.Decrypt(key, 'v3.local.AA', options as never),
      /"options" must be an object/u,
    )
  }

  const WrapFactory = LocalWrapKeyWithPassword<1, Key>({
    version: 1,
    async run() {
      return 'k1.local-pw.payload'
    },
  })
  const UnwrapFactory = LocalUnwrapKeyWithPassword<1, Key>({
    version: 1,
    async run() {
      return key
    },
  })
  const password = new LocalProtocol(WrapFactory, UnwrapFactory)
  for (const options of invalidOptions) {
    await assert.rejects(
      password.WrapKeyWithPassword(key, new Uint8Array(), options as never),
      /"options" must be an object/u,
    )
    await assert.rejects(
      password.UnwrapKeyWithPassword('k1.local-pw.payload', new Uint8Array(), options as never),
      /"options" must be an object/u,
    )
  }
})

test('boolean options require booleans', async () => {
  const EncryptFactory = LocalEncrypt<3, Key>({
    version: 3,
    async run() {
      return Uint8Array.of(1)
    },
  })
  const encrypt = new LocalProtocol(EncryptFactory)

  await assert.rejects(
    encrypt.Encrypt(key, {}, { addIssuedAt: 1 } as never),
    /"addIssuedAt" must be a boolean/u,
  )
  await assert.rejects(
    encrypt.Encrypt(key, {}, { nonExpiring: 'yes' } as never),
    /"nonExpiring" must be a boolean/u,
  )

  const DecryptFactory = LocalDecrypt<3, Key>({
    version: 3,
    async run() {
      return new TextEncoder().encode('{"exp":"2999-01-01T00:00:00Z"}')
    },
  })
  const decrypt = new LocalProtocol(DecryptFactory)
  await assert.rejects(
    decrypt.Decrypt(key, 'v3.local.AA', { allowNonExpiring: 1 } as never),
    /"allowNonExpiring" must be a boolean/u,
  )
})

test('password options require positive safe integers', async () => {
  const WrapFactory = LocalWrapKeyWithPassword<1, Key>({
    version: 1,
    async run() {
      return 'k1.local-pw.payload'
    },
  })
  const wrap = new LocalProtocol(WrapFactory)

  await assert.rejects(
    wrap.WrapKeyWithPassword(key, new Uint8Array(), { iterations: 0 }),
    /"iterations" must be a positive safe integer/u,
  )
  await assert.rejects(
    wrap.WrapKeyWithPassword(key, new Uint8Array(), { iterations: 1.5 }),
    /"iterations" must be a positive safe integer/u,
  )
})
