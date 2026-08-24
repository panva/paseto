import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  InvalidKeyError,
  InvalidPASERKError,
  LocalProtocol,
  PasetoError,
  PublicProtocol,
} from '../index.ts'
import { ImportKeyFactory as ImportLocalKeyV1 } from '../v1/local.ts'
import {
  ImportPublicKeyFactory as ImportPublicKeyV1,
  ImportSecretKeyFactory as ImportSecretKeyV1,
} from '../v1/public.ts'
import { ImportKeyFactory as ImportLocalKeyV2 } from '../v2/local.ts'
import {
  ImportPublicKeyFactory as ImportPublicKeyV2,
  ImportSecretKeyFactory as ImportSecretKeyV2,
} from '../v2/public.ts'
import { ImportKeyFactory as ImportLocalKeyV3 } from '../v3/local.ts'
import {
  ImportPublicKeyFactory as ImportPublicKeyV3,
  ImportSecretKeyFactory as ImportSecretKeyV3,
} from '../v3/public.ts'
import { ImportKeyFactory as ImportLocalKeyV4 } from '../v4/local.ts'
import {
  ImportPublicKeyFactory as ImportPublicKeyV4,
  ImportSecretKeyFactory as ImportSecretKeyV4,
} from '../v4/public.ts'

type PaserkKeyType = 'local' | 'public' | 'secret'

interface LocalImporter {
  ImportKey(paserk: unknown): Promise<unknown>
}

interface PublicImporter {
  ImportPublicKey(paserk: unknown): Promise<unknown>
  ImportSecretKey(paserk: unknown): Promise<unknown>
}

function encodePaserk(version: number, type: PaserkKeyType, material: Uint8Array): string {
  let binary = ''
  for (const byte of material) binary += String.fromCharCode(byte)
  const payload = btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
  return `k${version}.${type}.${payload}`
}

test('InvalidPASERKError has a distinct stable code', () => {
  const error = new InvalidPASERKError()
  assert.equal(error.name, 'InvalidPASERKError')
  assert.equal(error.code, 'ERR_PASERK_INVALID')
  assert.equal(error.message, 'Invalid PASERK')
  assert(error instanceof PasetoError)
})

test('PASERK import errors distinguish syntax, arguments, and decoded key material', async (t) => {
  const implementations = [
    {
      version: 1,
      local: new LocalProtocol(ImportLocalKeyV1),
      public: new PublicProtocol(ImportPublicKeyV1, ImportSecretKeyV1),
    },
    {
      version: 2,
      local: new LocalProtocol(ImportLocalKeyV2),
      public: new PublicProtocol(ImportPublicKeyV2, ImportSecretKeyV2),
    },
    {
      version: 3,
      local: new LocalProtocol(ImportLocalKeyV3),
      public: new PublicProtocol(ImportPublicKeyV3, ImportSecretKeyV3),
    },
    {
      version: 4,
      local: new LocalProtocol(ImportLocalKeyV4),
      public: new PublicProtocol(ImportPublicKeyV4, ImportSecretKeyV4),
    },
  ] as const

  for (const implementation of implementations) {
    await t.test(`v${implementation.version}`, async () => {
      const local = implementation.local as unknown as LocalImporter
      const publicProtocol = implementation.public as unknown as PublicImporter
      const imports = {
        local: (paserk: unknown) => local.ImportKey(paserk),
        public: (paserk: unknown) => publicProtocol.ImportPublicKey(paserk),
        secret: (paserk: unknown) => publicProtocol.ImportSecretKey(paserk),
      } as const

      for (const type of ['local', 'public', 'secret'] as const) {
        await assert.rejects(
          imports[type](`k${implementation.version}.${type}.!`),
          InvalidPASERKError,
        )
        await assert.rejects(imports[type](undefined), TypeError)
        await assert.rejects(
          imports[type](encodePaserk(implementation.version, type, Uint8Array.of(0))),
          InvalidKeyError,
        )
      }

      if (implementation.version === 2 || implementation.version === 4) {
        await assert.rejects(
          imports.secret(encodePaserk(implementation.version, 'secret', new Uint8Array(64))),
          InvalidKeyError,
        )
      } else if (implementation.version === 3) {
        await assert.rejects(
          imports.public(encodePaserk(3, 'public', new Uint8Array(49))),
          InvalidKeyError,
        )
        await assert.rejects(
          imports.secret(encodePaserk(3, 'secret', new Uint8Array(48))),
          InvalidKeyError,
        )
      }
    })
  }
})
