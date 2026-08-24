import assert from 'node:assert/strict'
import { describe, test } from 'node:test'

import { InvalidKeyError, LocalProtocol, PublicProtocol, type Key } from '../index.ts'
import * as V1Local from '../v1/local.ts'
import * as V1Public from '../v1/public.ts'
import * as V2Local from '../v2/local.ts'
import * as V2Public from '../v2/public.ts'
import * as V3Local from '../v3/local.ts'
import * as V3Public from '../v3/public.ts'
import * as V4Local from '../v4/local.ts'
import * as V4Public from '../v4/public.ts'

interface WrappingKeyProtocol {
  GenerateWrappingKey(options?: { extractable?: boolean }): Promise<Key>
  ImportWrappingKey(material: Uint8Array, options?: { extractable?: boolean }): Promise<Key>
  ExportWrappingKey(key: Key): Promise<Uint8Array>
}

async function checkWrappingKeyExtractability(protocol: WrappingKeyProtocol): Promise<void> {
  const generated = await protocol.GenerateWrappingKey()
  assert.equal(generated.extractable, false)
  await assert.rejects(protocol.ExportWrappingKey(generated), InvalidKeyError)

  const exportable = await protocol.GenerateWrappingKey({ extractable: true })
  assert.equal(exportable.extractable, true)
  const material = await protocol.ExportWrappingKey(exportable)

  const imported = await protocol.ImportWrappingKey(material)
  assert.equal(imported.extractable, false)
  await assert.rejects(protocol.ExportWrappingKey(imported), InvalidKeyError)

  const importedExportable = await protocol.ImportWrappingKey(material, { extractable: true })
  assert.equal(importedExportable.extractable, true)
  assert.deepEqual(await protocol.ExportWrappingKey(importedExportable), material)
}

describe('auxiliary secret-key extractability', () => {
  const wrappingProtocols: WrappingKeyProtocol[] = [
    new LocalProtocol(
      V1Local.GenerateWrappingKeyFactory,
      V1Local.ImportWrappingKeyFactory,
      V1Local.ExportWrappingKeyFactory,
    ),
    new PublicProtocol(
      V1Public.GenerateWrappingKeyFactory,
      V1Public.ImportWrappingKeyFactory,
      V1Public.ExportWrappingKeyFactory,
    ),
    new LocalProtocol(
      V2Local.GenerateWrappingKeyFactory,
      V2Local.ImportWrappingKeyFactory,
      V2Local.ExportWrappingKeyFactory,
    ),
    new PublicProtocol(
      V2Public.GenerateWrappingKeyFactory,
      V2Public.ImportWrappingKeyFactory,
      V2Public.ExportWrappingKeyFactory,
    ),
    new LocalProtocol(
      V3Local.GenerateWrappingKeyFactory,
      V3Local.ImportWrappingKeyFactory,
      V3Local.ExportWrappingKeyFactory,
    ),
    new PublicProtocol(
      V3Public.GenerateWrappingKeyFactory,
      V3Public.ImportWrappingKeyFactory,
      V3Public.ExportWrappingKeyFactory,
    ),
    new LocalProtocol(
      V4Local.GenerateWrappingKeyFactory,
      V4Local.ImportWrappingKeyFactory,
      V4Local.ExportWrappingKeyFactory,
    ),
    new PublicProtocol(
      V4Public.GenerateWrappingKeyFactory,
      V4Public.ImportWrappingKeyFactory,
      V4Public.ExportWrappingKeyFactory,
    ),
  ]

  for (const [index, protocol] of wrappingProtocols.entries()) {
    test(`wrapping-key protocol ${index + 1} defaults to non-extractable`, async () => {
      await checkWrappingKeyExtractability(protocol)
    })
  }

  test('v3 sealing secret keys default to non-extractable', async () => {
    const protocol = new LocalProtocol(
      V3Local.GenerateSealingKeyPairFactory,
      V3Local.ImportSealingSecretKeyFactory,
      V3Local.ExportSealingSecretKeyFactory,
    )

    const generated = await protocol.GenerateSealingKeyPair()
    assert.equal(generated.secretKey.extractable, false)
    await assert.rejects(protocol.ExportSealingSecretKey(generated.secretKey), InvalidKeyError)

    const exportable = await protocol.GenerateSealingKeyPair({ extractable: true })
    assert.equal(exportable.secretKey.extractable, true)
    const material = await protocol.ExportSealingSecretKey(exportable.secretKey)

    const imported = await protocol.ImportSealingSecretKey(material)
    assert.equal(imported.extractable, false)
    await assert.rejects(protocol.ExportSealingSecretKey(imported), InvalidKeyError)

    const importedExportable = await protocol.ImportSealingSecretKey(material, {
      extractable: true,
    })
    assert.equal(importedExportable.extractable, true)
    assert.deepEqual(await protocol.ExportSealingSecretKey(importedExportable), material)
  })
})
