import assert from 'node:assert/strict'
import { test } from 'node:test'

import * as PASETO from '../index.ts'
import * as V1Local from '../v1/local.ts'
import * as V1Public from '../v1/public.ts'
import * as V2Local from '../v2/local.ts'
import * as V3Local from '../v3/local.ts'
import { factoryTuple } from './helpers/factories.ts'

const LocalProtocolRuntime = PASETO.LocalProtocol as unknown as new (
  ...factories: unknown[]
) => object
const PublicProtocolRuntime = PASETO.PublicProtocol as unknown as new (
  ...factories: unknown[]
) => object

test('protocol constructors expose their public names', () => {
  assert.equal(PASETO.LocalProtocol.name, 'LocalProtocol')
  assert.equal(PASETO.PublicProtocol.name, 'PublicProtocol')
})

test('implementations stay dormant until their operation is called', async () => {
  let calls = 0
  const GenerateKeyFactory = PASETO.LocalGenerateKey<1, PASETO.Key>({
    version: 1,
    run: async (extractable) => {
      calls++
      return { algorithm: { name: 'test' }, extractable, type: 'secret' }
    },
  })

  assert.equal(calls, 0)
  const protocol = new PASETO.LocalProtocol(GenerateKeyFactory)
  assert.equal(calls, 0)
  assert.equal((await protocol.GenerateKey({ extractable: true })).extractable, true)
  assert.equal(calls, 1)
})

test('composition accepts factories created by another paseto module instance', async () => {
  const foreign = (await import(
    new URL('../index.ts?foreign-copy', import.meta.url).href
  )) as typeof PASETO
  const GenerateKeyFactory = foreign.LocalGenerateKey<1, PASETO.Key>({
    version: 1,
    run: async (extractable) => ({ algorithm: { name: 'test' }, extractable, type: 'secret' }),
  })

  const protocol = new PASETO.LocalProtocol(GenerateKeyFactory)
  assert.equal(protocol.version, 1)
  assert.equal((await protocol.GenerateKey()).extractable, false)
})

test('composition normalizes errors from another paseto module instance', async () => {
  const foreign = (await import(
    new URL('../index.ts?foreign-error-copy', import.meta.url).href
  )) as typeof PASETO
  const GenerateKeyFactory = foreign.LocalGenerateKey<1, PASETO.Key>({
    version: 1,
    run: async () => {
      throw new foreign.ClaimValidationError('Unexpected "sub" claim', 'sub')
    },
  })
  const protocol = new PASETO.LocalProtocol(GenerateKeyFactory)

  await assert.rejects(protocol.GenerateKey(), (error: unknown) => {
    assert(error instanceof PASETO.ClaimValidationError)
    assert.equal(error.code, 'ERR_PASETO_CLAIM_VALIDATION')
    assert.equal(error.message, 'Unexpected "sub" claim')
    assert.equal(error.claim, 'sub')
    return true
  })
})

test('adapted token capabilities reject implementation metadata changes after composition', async () => {
  let originalCalls = 0
  let replacementCalls = 0
  const originalRun: PASETO.LocalEncryptImplementation<3, PASETO.Key>['run'] = async () => {
    originalCalls++
    return Uint8Array.of(1, 2, 3)
  }
  const replacementRun: typeof originalRun = async () => {
    replacementCalls++
    return Uint8Array.of(4, 5, 6)
  }
  const implementation = { version: 3, run: originalRun } as {
    version: PASETO.Version
    run: typeof originalRun
  }
  const EncryptFactory = PASETO.LocalEncrypt<3, PASETO.Key>(
    implementation as PASETO.LocalEncryptImplementation<3, PASETO.Key>,
  )
  const protocol = new PASETO.LocalProtocol(EncryptFactory)

  implementation.version = 4
  implementation.run = replacementRun

  const key: PASETO.Key = { algorithm: { name: 'test' }, extractable: false, type: 'secret' }
  assert.equal(protocol.version, 3)
  await assert.rejects(
    protocol.Encrypt(key, {}, { addIssuedAt: false, nonExpiring: true }),
    /implementation version or run changed after composition/u,
  )
  assert.equal(originalCalls, 0)
  assert.equal(replacementCalls, 0)
})

test('direct PASERK capabilities reject implementation metadata changes after composition', async () => {
  let originalCalls = 0
  let replacementCalls = 0
  const originalRun: PASETO.LocalKeyIDImplementation<3>['run'] = async () => {
    originalCalls++
    return 'k3.lid.original'
  }
  const replacementRun: typeof originalRun = async () => {
    replacementCalls++
    return 'k3.lid.replacement'
  }
  const implementation = { version: 3, run: originalRun } as {
    version: PASETO.Version
    run: typeof originalRun
  }
  const KeyIDFactory = PASETO.LocalKeyID<3>(implementation as PASETO.LocalKeyIDImplementation<3>)
  const protocol = new PASETO.LocalProtocol(KeyIDFactory)

  implementation.version = 4
  implementation.run = replacementRun

  assert.equal(protocol.version, 3)
  await assert.rejects(
    protocol.KeyID('k3.local.AA'),
    /implementation version or run changed after composition/u,
  )
  assert.equal(originalCalls, 0)
  assert.equal(replacementCalls, 0)
})

test('method-style implementations retain their original receiver state', async () => {
  class Implementation {
    version = 3
    #suffix = 'state'

    async run() {
      return `k${this.version}.lid.${this.#suffix}`
    }
  }
  const implementation = new Implementation()
  const KeyIDFactory = PASETO.LocalKeyID<3>(implementation as PASETO.LocalKeyIDImplementation<3>)
  const protocol = new PASETO.LocalProtocol(KeyIDFactory)

  assert.equal(protocol.version, 3)
  assert.equal(await protocol.KeyID('k3.local.AA'), 'k3.lid.state')
})

test('pending operations reject implementation metadata changes', async () => {
  let release!: () => void
  const gate = new Promise<void>((resolve) => {
    release = resolve
  })
  const implementation = {
    version: 3,
    async run() {
      await gate
      return `k${this.version}.lid.pending`
    },
  } as { version: PASETO.Version; run: PASETO.LocalKeyIDImplementation<3>['run'] }
  const KeyIDFactory = PASETO.LocalKeyID<3>(implementation as PASETO.LocalKeyIDImplementation<3>)
  const protocol = new PASETO.LocalProtocol(KeyIDFactory)

  const pending = protocol.KeyID('k3.local.AA')
  implementation.version = 4
  release()

  await assert.rejects(pending, /implementation version or run changed after composition/u)
})

test('composition rejects factories not produced by an operation creator', () => {
  let calls = 0
  const forgedLocalFactory = () => {
    calls++
    return {
      purpose: 'local',
      version: 3,
      operation: 'Decrypt',
      run: async () => ({ claims: {}, footer: new Uint8Array() }),
    }
  }
  Object.defineProperty(forgedLocalFactory, '__pasetoCapabilityFactory', { value: true })
  const forgedPublicFactory = () => {
    calls++
    return {
      purpose: 'public',
      version: 4,
      operation: 'Verify',
      run: async () => ({ claims: {}, footer: new Uint8Array() }),
    }
  }
  const rejectsForgery = (error: unknown) =>
    error instanceof TypeError &&
    error.message === 'Invalid capability factory' &&
    error.cause instanceof TypeError &&
    /capability factory is not recognized/u.test(error.cause.message)

  assert.throws(() => new LocalProtocolRuntime(forgedLocalFactory), rejectsForgery)
  assert.throws(() => new PublicProtocolRuntime(forgedPublicFactory), rejectsForgery)
  assert.equal(calls, 0)
})

test('a protocol exposes exactly the selected capabilities', () => {
  const protocol = new PASETO.LocalProtocol(V3Local.DecryptFactory, V3Local.ImportKeyFactory)

  assert.equal('Decrypt' in protocol, true)
  assert.equal('Encrypt' in protocol, false)
  assert.equal('InspectFooter' in protocol, false)
  assert.equal('PASERK' in protocol, false)
  assert.deepEqual(Object.keys(protocol).sort(), ['Decrypt', 'ImportKey', 'purpose', 'version'])
})

test('built-in subpaths omit operations unavailable through Web Cryptography', () => {
  const protocol = new PASETO.LocalProtocol(...factoryTuple(V2Local))

  assert.equal('Encrypt' in protocol, false)
  assert.equal('Decrypt' in protocol, false)
  assert.equal('KeyID' in protocol, false)
  assert.equal('WrapKey' in protocol, false)
})

test('composition requires at least one capability', () => {
  assert.throws(() => new LocalProtocolRuntime(), /at least one capability factory is required/u)
})

test('composition rejects mixed versions', () => {
  assert.throws(
    () => new LocalProtocolRuntime(V1Local.GenerateKeyFactory, V3Local.ImportKeyFactory),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'Invalid "ImportKey" capability' &&
      error.cause instanceof TypeError &&
      /version does not match/u.test(error.cause.message),
  )
})

test('composition rejects a capability from the other purpose', () => {
  assert.throws(
    () => new LocalProtocolRuntime(V1Public.GenerateKeyPairFactory),
    (error: unknown) =>
      error instanceof TypeError &&
      error.message === 'Invalid "GenerateKeyPair" capability' &&
      error.cause instanceof TypeError &&
      /purpose does not match/u.test(error.cause.message),
  )
})

test('composition rejects duplicate capabilities', () => {
  assert.throws(
    () => new LocalProtocolRuntime(V1Local.EncryptFactory, V1Local.EncryptFactory),
    /Duplicate "Encrypt" capability/u,
  )
})
