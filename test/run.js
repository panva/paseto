// Shared runtime-neutral test logic for browsers and workerd.

const encoder = new TextEncoder()

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${String(expected)}, received ${String(actual)}`)
  }
}

function assertBytesEqual(actual, expected, message) {
  assert(actual instanceof Uint8Array, `${message}: result is not a Uint8Array`)
  assertEqual(actual.byteLength, expected.byteLength, `${message}: length mismatch`)
  for (let index = 0; index < actual.byteLength; index++) {
    if (actual[index] !== expected[index]) {
      throw new Error(`${message}: byte ${index} differs`)
    }
  }
}

function assertJsonEqual(actual, expected, message) {
  assertEqual(JSON.stringify(actual), JSON.stringify(expected), message)
}

async function expectReject(operation, ErrorConstructor, message) {
  try {
    await operation
  } catch (error) {
    if (error instanceof ErrorConstructor) return
    throw new Error(`${message}: rejected with ${error?.constructor?.name ?? typeof error}`, {
      cause: error,
    })
  }
  throw new Error(`${message}: operation resolved`)
}

function fromHex(input) {
  assert(/^(?:[0-9a-f]{2})*$/iu.test(input), 'Invalid hexadecimal vector field')
  const output = new Uint8Array(input.length / 2)
  for (let index = 0; index < output.byteLength; index++) {
    output[index] = Number.parseInt(input.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

function decodePem(input) {
  const base64 = input
    .replace(/^-----BEGIN [^-]+-----$/gmu, '')
    .replace(/^-----END [^-]+-----$/gmu, '')
    .replace(/\s/gu, '')
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0))
}

function base64url(input) {
  // @ts-ignore Uint8Array Base64 methods are not yet available in every runtime.
  if (typeof input.toBase64 === 'function') {
    return input.toBase64({ alphabet: 'base64url', omitPadding: true })
  }
  let binary = ''
  for (const byte of input) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function localPaserk(version, material) {
  return `k${version}.local.${base64url(fromHex(material))}`
}

function publicPaserk(version, material) {
  const bytes = material.startsWith('-----BEGIN ') ? decodePem(material) : fromHex(material)
  return `k${version}.public.${base64url(bytes)}`
}

async function nonExtractablePublicCryptoKey(version, key) {
  if (version === 1) {
    return crypto.subtle.importKey(
      'spki',
      await crypto.subtle.exportKey('spki', key),
      { name: 'RSA-PSS', hash: 'SHA-384' },
      false,
      ['verify'],
    )
  }

  const raw = await crypto.subtle.exportKey('raw', key)
  const algorithm = version === 3 ? { name: 'ECDSA', namedCurve: 'P-384' } : 'Ed25519'
  return crypto.subtle.importKey('raw', raw, algorithm, false, ['verify'])
}

function passwordOptions(version) {
  return version === 1 || version === 3
    ? { iterations: 1 }
    : { memory: 8 * 1024, passes: 1, parallelism: 1 }
}

function protocolOptions(version) {
  const footer = encoder.encode('runtime-test-footer')
  const implicitAssertion =
    version >= 3 ? { implicitAssertion: encoder.encode('runtime-test-assertion') } : {}
  return {
    produce: { footer, ...implicitAssertion, addIssuedAt: false, nonExpiring: true },
    consume: { footer, ...implicitAssertion, allowNonExpiring: true },
  }
}

function tamperToken(token) {
  const index = token.lastIndexOf('.') + 1
  const replacement = token[index] === 'A' ? 'B' : 'A'
  return `${token.slice(0, index)}${replacement}${token.slice(index + 1)}`
}

function capabilityFactories(module) {
  const marker = Symbol.for('panva.paseto.capabilityFactory')
  return Object.values(module).filter(
    (value) => typeof value === 'function' && value[marker] === true,
  )
}

function createImplementations(Native, Noble, mode) {
  const onlyNative = mode.onlyNative === true
  const onlyReference = mode.onlyReference === true
  const both = (onlyNative && onlyReference) || (!onlyNative && !onlyReference)
  const implementations = []

  if (both || onlyNative) {
    for (const version of [1, 2, 3, 4]) {
      implementations.push({
        label: 'native',
        version,
        localCapabilities: Native[`V${version}_LOCAL`],
        publicCapabilities: Native[`V${version}_PUBLIC`],
        localSupported: version === 1 || version === 3,
        protectedPaserkSupported: version === 1 || version === 3,
        sealSupported: version === 3,
      })
    }
  }

  if (both || onlyReference) {
    for (const version of [2, 4]) {
      const options = { argon2id: Noble.KDF_ARGON2ID_NOBLE }
      implementations.push({
        label: 'extensibility',
        version,
        localCapabilities: Noble.createLocalCapabilities(version, options),
        publicCapabilities: Noble.createPublicCapabilities(version, options),
        localSupported: true,
        protectedPaserkSupported: true,
        sealSupported: true,
      })
    }
  }

  return implementations
}

async function testLocalProtocol(PASETO, implementation) {
  const protocol = new PASETO.LocalProtocol(
    ...capabilityFactories(implementation.localCapabilities),
  )
  const key = await protocol.GenerateKey({ extractable: true })
  const serialized = await protocol.ExportKey(key)
  const imported = await protocol.ImportKey(serialized, { extractable: true })
  assertEqual(await protocol.ExportKey(imported), serialized, 'local PASERK round-trip')

  if (
    typeof implementation.localCapabilities.LocalKeyFromCryptoKey === 'function' &&
    typeof implementation.localCapabilities.LocalKeyToCryptoKey === 'function'
  ) {
    const cryptoKey = implementation.localCapabilities.LocalKeyToCryptoKey(key)
    const rebound = implementation.localCapabilities.LocalKeyFromCryptoKey(cryptoKey)
    assertEqual(
      implementation.localCapabilities.LocalKeyToCryptoKey(rebound),
      cryptoKey,
      'local CryptoKey identity',
    )
    assertEqual(rebound.extractable, false, 'native HKDF key remains non-extractable')
    await expectReject(
      protocol.ExportKey(rebound),
      PASETO.InvalidKeyError,
      'CryptoKey-backed local key export',
    )

    const options = protocolOptions(implementation.version)
    const token = await protocol.Encrypt(rebound, { sub: 'cryptokey-adapter' }, options.produce)
    const result = await protocol.Decrypt(rebound, token, options.consume)
    assertEqual(result.claims.sub, 'cryptokey-adapter', 'CryptoKey-backed local token claims')
  }

  if (!implementation.localSupported) {
    assert(!('Encrypt' in protocol), `v${implementation.version}.local unexpectedly has Encrypt`)
    assert(!('Decrypt' in protocol), `v${implementation.version}.local unexpectedly has Decrypt`)
    assert(!('KeyID' in protocol), `k${implementation.version} unexpectedly has KeyID`)
    return
  }

  const options = protocolOptions(implementation.version)
  const token = await protocol.Encrypt(key, { sub: 'runtime-test' }, options.produce)
  const result = await protocol.Decrypt(imported, token, options.consume)
  assertEqual(result.claims.sub, 'runtime-test', 'local token claims')
  assertBytesEqual(result.footer, options.produce.footer, 'local token footer')
  await expectReject(
    protocol.Decrypt(imported, tamperToken(token), options.consume),
    PASETO.InvalidTokenError,
    'tampered local token',
  )
  if (implementation.version >= 3) {
    await expectReject(
      protocol.Decrypt(imported, token, {
        ...options.consume,
        implicitAssertion: encoder.encode('incorrect-runtime-test-assertion'),
      }),
      PASETO.InvalidTokenError,
      'incorrect local implicit assertion',
    )
  }

  const id = await protocol.KeyID(serialized)
  assert(id.startsWith(`k${implementation.version}.lid.`), 'invalid local PASERK ID')

  const wrappingKey = await protocol.GenerateWrappingKey()
  assertEqual(wrappingKey.extractable, false, 'generated wrapping key defaults to non-extractable')
  await expectReject(
    protocol.ExportWrappingKey(wrappingKey),
    PASETO.InvalidKeyError,
    'non-extractable generated wrapping key export',
  )
  const exportableWrappingKey = await protocol.GenerateWrappingKey({ extractable: true })
  const wrappingKeyMaterial = await protocol.ExportWrappingKey(exportableWrappingKey)
  const importedWrappingKey = await protocol.ImportWrappingKey(wrappingKeyMaterial)
  assertEqual(
    importedWrappingKey.extractable,
    false,
    'imported wrapping key defaults to non-extractable',
  )
  await expectReject(
    protocol.ExportWrappingKey(importedWrappingKey),
    PASETO.InvalidKeyError,
    'non-extractable imported wrapping key export',
  )
  assertBytesEqual(
    await protocol.ExportWrappingKey(
      await protocol.ImportWrappingKey(wrappingKeyMaterial, { extractable: true }),
    ),
    wrappingKeyMaterial,
    'extractable wrapping key import',
  )
  const wrapped = await protocol.WrapKey(key, wrappingKey)
  assert(
    (await protocol.KeyID(wrapped)).startsWith(`k${implementation.version}.lid.`),
    'invalid wrapped local PASERK ID',
  )
  const unwrapped = await protocol.UnwrapKey(wrapped, wrappingKey, { extractable: true })
  assertEqual(await protocol.ExportKey(unwrapped), serialized, 'local PIE round-trip')

  const password = encoder.encode('runtime-test-password')
  const passwordWrapped = await protocol.WrapKeyWithPassword(
    key,
    password,
    passwordOptions(implementation.version),
  )
  const passwordUnwrapped = await protocol.UnwrapKeyWithPassword(passwordWrapped, password, {
    extractable: true,
  })
  assertEqual(
    await protocol.ExportKey(passwordUnwrapped),
    serialized,
    'local password wrap round-trip',
  )

  if (implementation.sealSupported) {
    const recipient = await protocol.GenerateSealingKeyPair()
    assertEqual(
      recipient.secretKey.extractable,
      false,
      'generated sealing secret key defaults to non-extractable',
    )
    await expectReject(
      protocol.ExportSealingSecretKey(recipient.secretKey),
      PASETO.InvalidKeyError,
      'non-extractable generated sealing secret key export',
    )
    const exportableRecipient = await protocol.GenerateSealingKeyPair({ extractable: true })
    const sealingSecretMaterial = await protocol.ExportSealingSecretKey(
      exportableRecipient.secretKey,
    )
    const importedRecipient = await protocol.ImportSealingSecretKey(sealingSecretMaterial)
    assertEqual(
      importedRecipient.extractable,
      false,
      'imported sealing secret key defaults to non-extractable',
    )
    await expectReject(
      protocol.ExportSealingSecretKey(importedRecipient),
      PASETO.InvalidKeyError,
      'non-extractable imported sealing secret key export',
    )
    assertBytesEqual(
      await protocol.ExportSealingSecretKey(
        await protocol.ImportSealingSecretKey(sealingSecretMaterial, { extractable: true }),
      ),
      sealingSecretMaterial,
      'extractable sealing secret key import',
    )
    const sealed = await protocol.SealKey(key, recipient.publicKey)
    const unsealed = await protocol.UnsealKey(sealed, recipient.secretKey, { extractable: true })
    assertEqual(await protocol.ExportKey(unsealed), serialized, 'local seal round-trip')
  }
}

async function testPublicProtocol(PASETO, implementation) {
  const protocol = new PASETO.PublicProtocol(
    ...capabilityFactories(implementation.publicCapabilities),
  )
  const { publicKey, secretKey } = await protocol.GenerateKeyPair({ extractable: true })
  const publicPaserk = await protocol.ExportPublicKey(publicKey)
  const secretPaserk = await protocol.ExportSecretKey(secretKey)
  const importedPublic = await protocol.ImportPublicKey(publicPaserk)
  const importedSecret = await protocol.ImportSecretKey(secretPaserk, { extractable: true })
  assertEqual(
    await protocol.ExportPublicKey(importedPublic),
    publicPaserk,
    'public PASERK round-trip',
  )
  assertEqual(
    await protocol.ExportSecretKey(importedSecret),
    secretPaserk,
    'secret PASERK round-trip',
  )

  if (
    typeof implementation.publicCapabilities.PublicKeyFromCryptoKey === 'function' &&
    typeof implementation.publicCapabilities.PublicKeyToCryptoKey === 'function'
  ) {
    const cryptoKey = implementation.publicCapabilities.PublicKeyToCryptoKey(publicKey)
    const rebound = await implementation.publicCapabilities.PublicKeyFromCryptoKey(cryptoKey)
    assertEqual(
      implementation.publicCapabilities.PublicKeyToCryptoKey(rebound),
      cryptoKey,
      'public CryptoKey identity',
    )
    assertEqual(
      await protocol.ExportPublicKey(rebound),
      publicPaserk,
      'extractable CryptoKey-backed public PASERK',
    )

    const nonExtractable = await nonExtractablePublicCryptoKey(implementation.version, cryptoKey)
    if (implementation.version === 3) {
      await expectReject(
        implementation.publicCapabilities.PublicKeyFromCryptoKey(nonExtractable),
        PASETO.InvalidKeyError,
        'non-extractable v3 public CryptoKey',
      )
    } else {
      const nonExtractableRebound =
        await implementation.publicCapabilities.PublicKeyFromCryptoKey(nonExtractable)
      assertEqual(
        implementation.publicCapabilities.PublicKeyToCryptoKey(nonExtractableRebound),
        nonExtractable,
        'non-extractable public CryptoKey identity',
      )
      assertEqual(
        nonExtractableRebound.extractable,
        false,
        'native public key remains non-extractable',
      )
      await expectReject(
        protocol.ExportPublicKey(nonExtractableRebound),
        PASETO.InvalidKeyError,
        'CryptoKey-backed public key export',
      )
      const adapterOptions = protocolOptions(implementation.version)
      const token = await protocol.Sign(
        secretKey,
        { sub: 'public-cryptokey-adapter' },
        adapterOptions.produce,
      )
      const result = await protocol.Verify(nonExtractableRebound, token, adapterOptions.consume)
      assertEqual(
        result.claims.sub,
        'public-cryptokey-adapter',
        'CryptoKey-backed public verification',
      )
    }
  }

  if (
    typeof implementation.publicCapabilities.SecretKeyFromCryptoKey === 'function' &&
    typeof implementation.publicCapabilities.SecretKeyToCryptoKey === 'function'
  ) {
    const cryptoKey = implementation.publicCapabilities.SecretKeyToCryptoKey(secretKey)
    const rebound = await implementation.publicCapabilities.SecretKeyFromCryptoKey(cryptoKey)
    assertEqual(
      implementation.publicCapabilities.SecretKeyToCryptoKey(rebound),
      cryptoKey,
      'secret CryptoKey identity',
    )
    assertEqual(
      await protocol.ExportSecretKey(rebound),
      secretPaserk,
      'extractable CryptoKey-backed secret PASERK',
    )

    if (typeof crypto.subtle.getPublicKey === 'function') {
      const generated = await protocol.GenerateKeyPair()
      const nonExtractable = implementation.publicCapabilities.SecretKeyToCryptoKey(
        generated.secretKey,
      )
      const nonExtractableRebound =
        await implementation.publicCapabilities.SecretKeyFromCryptoKey(nonExtractable)
      assertEqual(
        implementation.publicCapabilities.SecretKeyToCryptoKey(nonExtractableRebound),
        nonExtractable,
        'non-extractable secret CryptoKey identity',
      )
      assertEqual(
        nonExtractableRebound.extractable,
        false,
        'native private key remains non-extractable',
      )
      await expectReject(
        protocol.ExportSecretKey(nonExtractableRebound),
        PASETO.InvalidKeyError,
        'CryptoKey-backed secret key export',
      )
      const adapterOptions = protocolOptions(implementation.version)
      const token = await protocol.Sign(
        nonExtractableRebound,
        { sub: 'cryptokey-adapter' },
        adapterOptions.produce,
      )
      const result = await protocol.Verify(generated.publicKey, token, adapterOptions.consume)
      assertEqual(result.claims.sub, 'cryptokey-adapter', 'CryptoKey-backed public token claims')
    }
  }

  const derivedPublic = await protocol.GetPublicKey(importedSecret)
  assertEqual(await protocol.ExportPublicKey(derivedPublic), publicPaserk, 'derived public key')
  if (typeof implementation.publicCapabilities.PublicKeyToCryptoKey === 'function') {
    assertEqual(
      Reflect.get(
        implementation.publicCapabilities.PublicKeyToCryptoKey(importedPublic),
        Symbol.toStringTag,
      ),
      'CryptoKey',
      'imported public key retains a CryptoKey',
    )
    assertEqual(
      Reflect.get(
        implementation.publicCapabilities.PublicKeyToCryptoKey(derivedPublic),
        Symbol.toStringTag,
      ),
      'CryptoKey',
      'derived public key retains a CryptoKey',
    )
  }

  if (implementation.version === 3) {
    const generatorSecret = await protocol.ImportSecretKey(
      'k3.secret.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB',
    )
    const generatorPublic = await protocol.GetPublicKey(generatorSecret)
    assertEqual(
      await protocol.ExportPublicKey(generatorPublic),
      'k3.public.A6qHyiK-iwU3jrHHHvMgrXRuHTtii6ebmFn3QeCCVCo4VQLyXb9VKWw6VF44cnYKtw',
      'P-384 generator public key',
    )
  }

  const options = protocolOptions(implementation.version)
  const token = await protocol.Sign(importedSecret, { sub: 'runtime-test' }, options.produce)
  const result = await protocol.Verify(importedPublic, token, options.consume)
  assertEqual(result.claims.sub, 'runtime-test', 'public token claims')
  assertBytesEqual(result.footer, options.produce.footer, 'public token footer')
  await expectReject(
    protocol.Verify(importedPublic, tamperToken(token), options.consume),
    PASETO.InvalidTokenError,
    'tampered public token',
  )
  if (implementation.version >= 3) {
    await expectReject(
      protocol.Verify(importedPublic, token, {
        ...options.consume,
        implicitAssertion: encoder.encode('incorrect-runtime-test-assertion'),
      }),
      PASETO.InvalidTokenError,
      'incorrect public implicit assertion',
    )
  }

  if (!implementation.protectedPaserkSupported) {
    assert(!('PublicKeyID' in protocol), `k${implementation.version} unexpectedly has PublicKeyID`)
    assert(
      !('WrapSecretKey' in protocol),
      `k${implementation.version} unexpectedly has WrapSecretKey`,
    )
    return
  }

  assert(
    (await protocol.PublicKeyID(publicPaserk)).startsWith(`k${implementation.version}.pid.`),
    'invalid public PASERK ID',
  )
  assert(
    (await protocol.SecretKeyID(secretPaserk)).startsWith(`k${implementation.version}.sid.`),
    'invalid secret PASERK ID',
  )

  const wrappingKey = await protocol.GenerateWrappingKey()
  assertEqual(wrappingKey.extractable, false, 'generated wrapping key defaults to non-extractable')
  await expectReject(
    protocol.ExportWrappingKey(wrappingKey),
    PASETO.InvalidKeyError,
    'non-extractable generated wrapping key export',
  )
  const exportableWrappingKey = await protocol.GenerateWrappingKey({ extractable: true })
  const wrappingKeyMaterial = await protocol.ExportWrappingKey(exportableWrappingKey)
  const importedWrappingKey = await protocol.ImportWrappingKey(wrappingKeyMaterial)
  assertEqual(
    importedWrappingKey.extractable,
    false,
    'imported wrapping key defaults to non-extractable',
  )
  await expectReject(
    protocol.ExportWrappingKey(importedWrappingKey),
    PASETO.InvalidKeyError,
    'non-extractable imported wrapping key export',
  )
  assertBytesEqual(
    await protocol.ExportWrappingKey(
      await protocol.ImportWrappingKey(wrappingKeyMaterial, { extractable: true }),
    ),
    wrappingKeyMaterial,
    'extractable wrapping key import',
  )
  const wrapped = await protocol.WrapSecretKey(importedSecret, wrappingKey)
  assert(
    (await protocol.SecretKeyID(wrapped)).startsWith(`k${implementation.version}.sid.`),
    'invalid wrapped secret PASERK ID',
  )
  const unwrapped = await protocol.UnwrapSecretKey(wrapped, wrappingKey, { extractable: true })
  assertEqual(await protocol.ExportSecretKey(unwrapped), secretPaserk, 'secret PIE round-trip')

  const password = encoder.encode('runtime-test-password')
  const passwordWrapped = await protocol.WrapSecretKeyWithPassword(
    importedSecret,
    password,
    passwordOptions(implementation.version),
  )
  const passwordUnwrapped = await protocol.UnwrapSecretKeyWithPassword(passwordWrapped, password, {
    extractable: true,
  })
  assertEqual(
    await protocol.ExportSecretKey(passwordUnwrapped),
    secretPaserk,
    'secret password wrap round-trip',
  )
}

function vectorOptions(version, vector) {
  const options = {
    footer: encoder.encode(vector.footer),
    now: new Date(version < 3 ? '2018-01-01T00:00:00Z' : '2021-01-01T00:00:00Z'),
  }
  if (version >= 3) options.implicitAssertion = encoder.encode(vector['implicit-assertion'])
  return options
}

async function validateVectors(PASETO, implementation, vectors, purpose) {
  const protocol =
    purpose === 'local'
      ? new PASETO.LocalProtocol(...capabilityFactories(implementation.localCapabilities))
      : new PASETO.PublicProtocol(...capabilityFactories(implementation.publicCapabilities))

  for (const vector of vectors.tests) {
    const vectorPurpose = vector.key === undefined ? 'public' : 'local'
    if (vectorPurpose !== purpose) continue

    try {
      const options = vectorOptions(implementation.version, vector)
      let operation
      if (purpose === 'local') {
        const key = await protocol.ImportKey(localPaserk(implementation.version, vector.key))
        operation = protocol.Decrypt(key, vector.token, options)
      } else {
        const key = await protocol.ImportPublicKey(
          publicPaserk(implementation.version, vector['public-key']),
        )
        operation = protocol.Verify(key, vector.token, options)
      }

      if (vector['expect-fail']) {
        await expectReject(operation, PASETO.InvalidTokenError, vector.name)
        continue
      }

      const result = await operation
      assertJsonEqual(result.claims, JSON.parse(vector.payload), `${vector.name} claims`)
      assertBytesEqual(result.footer, encoder.encode(vector.footer), `${vector.name} footer`)
    } catch (cause) {
      throw new Error(`${vector.name}: ${cause.message}`, { cause })
    }
  }
}

/** Run the portable PASETO/PASERK runtime matrix. */
export async function runRuntimeTests({
  PASETO,
  Native,
  Noble,
  vectors,
  mode = {},
  onTestComplete,
}) {
  const tests = []

  async function run(name, operation) {
    const test = { name, status: 'running', error: null }
    tests.push(test)
    try {
      await operation()
      test.status = 'passed'
    } catch (error) {
      test.status = 'failed'
      test.error = error?.stack ?? error?.message ?? String(error)
    }
    onTestComplete?.(test, tests)
  }

  for (const implementation of createImplementations(Native, Noble, mode)) {
    const prefix = `[${implementation.label}] v${implementation.version}`
    await run(`${prefix}.local round-trip`, () => testLocalProtocol(PASETO, implementation))
    await run(`${prefix}.public round-trip`, () => testPublicProtocol(PASETO, implementation))

    const versionVectors = vectors[implementation.version]
    if (implementation.localSupported) {
      await run(`${prefix}.local official vectors`, () =>
        validateVectors(PASETO, implementation, versionVectors, 'local'),
      )
    }
    await run(`${prefix}.public official vectors`, () =>
      validateVectors(PASETO, implementation, versionVectors, 'public'),
    )
  }

  return {
    total: tests.length,
    passed: tests.filter((test) => test.status === 'passed').length,
    failed: tests.filter((test) => test.status === 'failed').length,
    tests,
  }
}
