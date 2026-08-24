// Validates the exact npm artifact in an isolated installation so missing files, undeclared
// runtime imports, packaging mistakes, and basic runtime failures are caught before publication.
import { execFileSync } from 'node:child_process'
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm'

const localLegacy = [
  'GenerateKey',
  'Encrypt',
  'Decrypt',
  'ImportKey',
  'ExportKey',
  'KeyID',
  'GenerateWrappingKey',
  'ImportWrappingKey',
  'ExportWrappingKey',
  'WrapKey',
  'UnwrapKey',
  'WrapKeyWithPassword',
  'UnwrapKeyWithPassword',
]
const localModern = [
  'GenerateKey',
  'ImportKey',
  'ExportKey',
  'GenerateWrappingKey',
  'ImportWrappingKey',
  'ExportWrappingKey',
]
const localV3 = [
  ...localLegacy,
  'GenerateSealingKeyPair',
  'ImportSealingPublicKey',
  'ImportSealingSecretKey',
  'ExportSealingPublicKey',
  'ExportSealingSecretKey',
  'SealKey',
  'UnsealKey',
]
const publicCore = [
  'GenerateKeyPair',
  'Sign',
  'Verify',
  'ImportPublicKey',
  'ExportPublicKey',
  'ImportSecretKey',
  'ExportSecretKey',
  'GetPublicKey',
]
const publicModern = [
  ...publicCore,
  'GenerateWrappingKey',
  'ImportWrappingKey',
  'ExportWrappingKey',
]
const publicLegacy = [
  ...publicCore,
  'PublicKeyID',
  'SecretKeyID',
  'GenerateWrappingKey',
  'ImportWrappingKey',
  'ExportWrappingKey',
  'WrapSecretKey',
  'UnwrapSecretKey',
  'WrapSecretKeyWithPassword',
  'UnwrapSecretKeyWithPassword',
]

const factoryNames = (operations) => operations.map((operation) => `${operation}Factory`)
const localCryptoKeyHelpers = ['LocalKeyFromCryptoKey', 'LocalKeyToCryptoKey']
const publicCryptoKeyHelpers = ['PublicKeyFromCryptoKey', 'PublicKeyToCryptoKey']
const secretCryptoKeyHelpers = ['SecretKeyFromCryptoKey', 'SecretKeyToCryptoKey']

const subpaths = [
  {
    id: 'V1Local',
    path: 'v1/local',
    purpose: 'local',
    version: 1,
    factories: factoryNames(localLegacy),
    helpers: localCryptoKeyHelpers,
  },
  {
    id: 'V1Public',
    path: 'v1/public',
    purpose: 'public',
    version: 1,
    factories: factoryNames(publicLegacy),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
  {
    id: 'V2Local',
    path: 'v2/local',
    purpose: 'local',
    version: 2,
    factories: factoryNames(localModern),
    helpers: [],
  },
  {
    id: 'V2Public',
    path: 'v2/public',
    purpose: 'public',
    version: 2,
    factories: factoryNames(publicModern),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
  {
    id: 'V3Local',
    path: 'v3/local',
    purpose: 'local',
    version: 3,
    factories: factoryNames(localV3),
    helpers: localCryptoKeyHelpers,
  },
  {
    id: 'V3Public',
    path: 'v3/public',
    purpose: 'public',
    version: 3,
    factories: factoryNames(publicLegacy),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
  {
    id: 'V4Local',
    path: 'v4/local',
    purpose: 'local',
    version: 4,
    factories: factoryNames(localModern),
    helpers: [],
  },
  {
    id: 'V4Public',
    path: 'v4/public',
    purpose: 'public',
    version: 4,
    factories: factoryNames(publicModern),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
]

function run(command, args, cwd = root) {
  execFileSync(command, args, { cwd, stdio: 'inherit' })
}

function manifest(directory) {
  return JSON.parse(readFileSync(join(directory, 'package.json'), 'utf8'))
}

function createTarball(destination) {
  mkdirSync(destination, { recursive: true })
  run(npm, ['pack', root, '--pack-destination', destination])
  const tarballs = readdirSync(destination).filter((entry) => entry.endsWith('.tgz'))
  if (tarballs.length !== 1) throw new Error(`npm pack produced ${tarballs.length} tarballs`)
  return join(destination, tarballs[0])
}

function listPackageFiles(directory, prefix = '') {
  const files = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (prefix === '' && entry.name === 'node_modules') continue
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      files.push(...listPackageFiles(join(directory, entry.name), relative))
    } else {
      files.push(relative)
    }
  }
  return files
}

function collectTypeScriptSources(directory, relative, sources) {
  const absolute = join(directory, relative)
  if (!existsSync(absolute)) return
  for (const entry of readdirSync(absolute, { withFileTypes: true })) {
    const path = `${relative}/${entry.name}`
    if (entry.isDirectory()) {
      collectTypeScriptSources(directory, path, sources)
    } else if (entry.isFile() && path.endsWith('.ts') && !path.endsWith('.d.ts')) {
      sources.push(path)
    }
  }
}

function expectedPackageFiles(directory) {
  const publicSources = ['index.ts']
  for (const { path } of subpaths) publicSources.push(`${path}.ts`)

  const internalSources = []
  collectTypeScriptSources(directory, '_internal', internalSources)

  for (const source of [...publicSources, ...internalSources]) {
    if (!existsSync(join(directory, source))) throw new Error(`${source} not found`)
  }
  if (internalSources.length === 0) throw new Error('no private runtime sources found')

  return [
    'LICENSE.md',
    'README.md',
    'package.json',
    ...publicSources.flatMap((source) => {
      const stem = source.slice(0, -3)
      return [source, `${stem}.js`, `${stem}.d.ts`, `${stem}.d.ts.map`]
    }),
    ...internalSources.map((source) => `${source.slice(0, -3)}.js`),
  ].sort()
}

function expectedExports() {
  return Object.fromEntries([
    ['.', { types: './index.d.ts', default: './index.js' }],
    ...subpaths.map(({ path }) => [
      `./${path}`,
      { types: `./${path}.d.ts`, default: `./${path}.js` },
    ]),
  ])
}

function smokeTestSource() {
  const imports = subpaths
    .map(({ id, path }) => `import * as ${id} from 'paseto/${path}'`)
    .join('\n')
  const descriptors = subpaths
    .map(
      ({ id, path, purpose, version, factories, helpers }) =>
        `{ label: ${JSON.stringify(path)}, purpose: ${JSON.stringify(purpose)}, version: ${version}, factories: ${JSON.stringify(factories)}, helpers: ${JSON.stringify(helpers)}, module: ${id} }`,
    )
    .join(',\n  ')
  const allSubpathExports = [
    ...new Set(subpaths.flatMap(({ factories, helpers }) => [...factories, ...helpers])),
  ].sort()
  const localCapabilities = [...new Set([...localV3])].sort()
  const publicCapabilities = [...new Set([...publicLegacy])].sort()

  return `import * as PASETO from 'paseto'
${imports}

const descriptors = [
  ${descriptors}
]
const purposeCapabilities = {
  local: ${JSON.stringify(localCapabilities)},
  public: ${JSON.stringify(publicCapabilities)},
}
const encoder = new TextEncoder()

function fail(message) {
  throw new Error(message)
}

function equalBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false
  for (let index = 0; index < left.byteLength; index++) {
    if (left[index] !== right[index]) return false
  }
  return true
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) fail(message + ': expected ' + expected + ', received ' + actual)
}

async function generateNativeKeyPair(version) {
  let algorithm
  if (version === 1) {
    algorithm = {
      name: 'RSA-PSS',
      modulusLength: 2048,
      publicExponent: Uint8Array.of(0x01, 0x00, 0x01),
      hash: 'SHA-384',
    }
  } else if (version === 3) {
    algorithm = { name: 'ECDSA', namedCurve: 'P-384' }
  } else {
    algorithm = 'Ed25519'
  }
  return await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])
}

async function makePublicKeyNonExtractable(version, key) {
  const format = version === 1 ? 'spki' : 'raw'
  const material = await crypto.subtle.exportKey(format, key)
  let algorithm
  if (version === 1) {
    algorithm = { name: 'RSA-PSS', hash: 'SHA-384' }
  } else if (version === 3) {
    algorithm = { name: 'ECDSA', namedCurve: 'P-384' }
  } else {
    algorithm = 'Ed25519'
  }
  return await crypto.subtle.importKey(format, material, algorithm, false, ['verify'])
}

if (typeof PASETO.LocalProtocol !== 'function') fail('missing LocalProtocol export')
if (typeof PASETO.PublicProtocol !== 'function') fail('missing PublicProtocol export')
if (typeof PASETO.InspectFooter !== 'function') fail('missing InspectFooter export')
const concreteRootExports = Object.keys(PASETO).filter(
  (name) =>
    /^V[1-4](?:_|$)/u.test(name) ||
    (name !== 'PublicKeyID' && ${JSON.stringify(allSubpathExports)}.includes(name)),
)
if (concreteRootExports.length !== 0) {
  fail('root exposes concrete protocol capabilities: ' + concreteRootExports.join(', '))
}

const protocols = []
for (const descriptor of descriptors) {
  const operations = descriptor.factories.map((name) => name.slice(0, -'Factory'.length))
  const actualExports = Object.keys(descriptor.module).sort()
  const expected = [...descriptor.factories, ...descriptor.helpers].sort()
  if (JSON.stringify(actualExports) !== JSON.stringify(expected)) {
    fail(
      descriptor.label + ' exports differ; expected ' + expected.join(', ') +
        '; received ' + actualExports.join(', '),
    )
  }
  for (const name of descriptor.factories) {
    if (typeof descriptor.module[name] !== 'function') {
      fail(descriptor.label + ' export ' + name + ' is not a capability factory')
    }
  }
  for (const name of descriptor.helpers) {
    if (typeof descriptor.module[name] !== 'function') {
      fail(descriptor.label + ' export ' + name + ' is not a direct helper')
    }
  }

  const Constructor = descriptor.purpose === 'local' ? PASETO.LocalProtocol : PASETO.PublicProtocol
  const protocol = new Constructor(...descriptor.factories.map((name) => descriptor.module[name]))
  assertEqual(protocol.version, descriptor.version, descriptor.label + ' version')
  assertEqual(protocol.purpose, descriptor.purpose, descriptor.label + ' purpose')
  if ('InspectFooter' in protocol) fail(descriptor.label + ' unexpectedly exposes InspectFooter')

  for (const name of purposeCapabilities[descriptor.purpose]) {
    const present = Object.hasOwn(protocol, name)
    if (present !== operations.includes(name)) {
      fail(
        descriptor.label + ' composed ' + name +
          (present ? ' despite its factory being absent' : ' factory was not installed'),
      )
    }
  }
  protocols.push({ ...descriptor, operations, protocol })
}

async function smokeLocal(descriptor) {
  const { label, operations, protocol, module, helpers } = descriptor
  const key = await protocol.GenerateKey({ extractable: true })
  const serialized = await protocol.ExportKey(key)
  const imported = await protocol.ImportKey(serialized, { extractable: true })
  assertEqual(await protocol.ExportKey(imported), serialized, label + ' key round trip')

  let operationalKey = imported
  if (helpers.includes('LocalKeyFromCryptoKey')) {
    if (module.LocalKeyToCryptoKey(imported)[Symbol.toStringTag] !== 'CryptoKey') {
      fail(label + ' imported local key did not retain a CryptoKey')
    }
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      crypto.getRandomValues(new Uint8Array(32)),
      'HKDF',
      false,
      ['deriveBits'],
    )
    operationalKey = module.LocalKeyFromCryptoKey(cryptoKey)
    if (module.LocalKeyToCryptoKey(operationalKey) !== cryptoKey) {
      fail(label + ' native local-key round trip did not retain CryptoKey identity')
    }
  }

  if (operations.includes('KeyID')) {
    assertEqual(
      await protocol.KeyID(await protocol.ExportKey(imported)),
      await protocol.KeyID(serialized),
      label + ' key identifier',
    )
  }

  if (operations.includes('Encrypt')) {
    const footer = encoder.encode(label)
    const token = await protocol.Encrypt(operationalKey, { sub: label }, { footer })
    if (!equalBytes(PASETO.InspectFooter(token), footer)) fail(label + ' footer inspection failed')
    const result = await protocol.Decrypt(operationalKey, token, { footer })
    assertEqual(result.claims.sub, label, label + ' token round trip')
  }

  const wrappingKey = await protocol.GenerateWrappingKey({ extractable: true })
  const wrappingMaterial = await protocol.ExportWrappingKey(wrappingKey)
  const importedWrappingKey = await protocol.ImportWrappingKey(wrappingMaterial, {
    extractable: true,
  })
  if (!equalBytes(await protocol.ExportWrappingKey(importedWrappingKey), wrappingMaterial)) {
    fail(label + ' wrapping-key round trip failed')
  }

  if (operations.includes('WrapKey')) {
    const wrapped = await protocol.WrapKey(imported, importedWrappingKey)
    const unwrapped = await protocol.UnwrapKey(wrapped, importedWrappingKey, {
      extractable: true,
    })
    assertEqual(await protocol.ExportKey(unwrapped), serialized, label + ' PIE round trip')

    const password = encoder.encode('artifact-smoke-password')
    const passwordWrapped = await protocol.WrapKeyWithPassword(imported, password, {
      iterations: 1_000,
    })
    const passwordUnwrapped = await protocol.UnwrapKeyWithPassword(
      passwordWrapped,
      password,
      { maxIterations: 1_000, extractable: true },
    )
    assertEqual(
      await protocol.ExportKey(passwordUnwrapped),
      serialized,
      label + ' password round trip',
    )
  }

  if (operations.includes('SealKey')) {
    const pair = await protocol.GenerateSealingKeyPair({ extractable: true })
    const publicMaterial = await protocol.ExportSealingPublicKey(pair.publicKey)
    const secretMaterial = await protocol.ExportSealingSecretKey(pair.secretKey)
    const publicKey = await protocol.ImportSealingPublicKey(publicMaterial)
    const secretKey = await protocol.ImportSealingSecretKey(secretMaterial, { extractable: true })
    const sealed = await protocol.SealKey(imported, publicKey)
    const unsealed = await protocol.UnsealKey(sealed, secretKey, { extractable: true })
    assertEqual(
      await protocol.ExportKey(unsealed),
      serialized,
      label + ' sealing round trip',
    )
  }
}

async function smokePublic(descriptor) {
  const { label, operations, protocol, module, helpers } = descriptor
  const pair = await protocol.GenerateKeyPair({ extractable: true })
  const publicSerialized = await protocol.ExportPublicKey(pair.publicKey)
  const secretSerialized = await protocol.ExportSecretKey(pair.secretKey)
  const publicKey = await protocol.ImportPublicKey(publicSerialized)
  const secretKey = await protocol.ImportSecretKey(secretSerialized, { extractable: true })
  assertEqual(
    await protocol.ExportPublicKey(publicKey),
    publicSerialized,
    label + ' public-key round trip',
  )
  assertEqual(
    await protocol.ExportSecretKey(secretKey),
    secretSerialized,
    label + ' secret-key round trip',
  )
  const derivedPublicKey = await protocol.GetPublicKey(secretKey)
  assertEqual(
    await protocol.ExportPublicKey(derivedPublicKey),
    publicSerialized,
    label + ' public-key derivation',
  )

  let signingKey = secretKey
  let verificationKey = publicKey
  const nativePair = helpers.some((name) => name.endsWith('KeyFromCryptoKey'))
    ? await generateNativeKeyPair(descriptor.version)
    : undefined
  if (helpers.includes('PublicKeyFromCryptoKey')) {
    for (const [source, key] of [
      ['generated', pair.publicKey],
      ['imported', publicKey],
      ['derived', derivedPublicKey],
    ]) {
      if (module.PublicKeyToCryptoKey(key)[Symbol.toStringTag] !== 'CryptoKey') {
        fail(label + ' ' + source + ' public key did not retain a CryptoKey')
      }
    }
    const cryptoKey = nativePair.publicKey
    verificationKey = await module.PublicKeyFromCryptoKey(cryptoKey)
    if (module.PublicKeyToCryptoKey(verificationKey) !== cryptoKey) {
      fail(label + ' native public-key round trip did not retain CryptoKey identity')
    }
    const nativePublicSerialized = await protocol.ExportPublicKey(verificationKey)
    const importedNativePublicKey = await protocol.ImportPublicKey(nativePublicSerialized)
    assertEqual(
      await protocol.ExportPublicKey(importedNativePublicKey),
      nativePublicSerialized,
      label + ' native public-key serialization round trip',
    )

    const nonExtractable = await makePublicKeyNonExtractable(descriptor.version, cryptoKey)
    if (descriptor.version === 3) {
      let rejected = false
      try {
        await module.PublicKeyFromCryptoKey(nonExtractable)
      } catch {
        rejected = true
      }
      if (!rejected) fail(label + ' accepted a non-extractable ECDSA public key')
    } else {
      verificationKey = await module.PublicKeyFromCryptoKey(nonExtractable)
      if (module.PublicKeyToCryptoKey(verificationKey) !== nonExtractable) {
        fail(label + ' non-extractable public-key round trip lost CryptoKey identity')
      }
      let rejected = false
      try {
        await protocol.ExportPublicKey(verificationKey)
      } catch {
        rejected = true
      }
      if (!rejected) fail(label + ' exported a non-extractable public key')
    }
  }
  if (helpers.includes('SecretKeyFromCryptoKey')) {
    if (module.SecretKeyToCryptoKey(secretKey)[Symbol.toStringTag] !== 'CryptoKey') {
      fail(label + ' imported secret key did not retain a CryptoKey')
    }
    const cryptoKey = nativePair.privateKey
    signingKey = await module.SecretKeyFromCryptoKey(cryptoKey)
    if (module.SecretKeyToCryptoKey(signingKey) !== cryptoKey) {
      fail(label + ' native secret-key round trip did not retain CryptoKey identity')
    }
    if (!helpers.includes('PublicKeyFromCryptoKey')) {
      verificationKey = await protocol.GetPublicKey(signingKey)
    }
  }

  const footer = encoder.encode(label)
  const token = await protocol.Sign(signingKey, { sub: label }, { footer })
  if (!equalBytes(PASETO.InspectFooter(token), footer)) fail(label + ' footer inspection failed')
  const result = await protocol.Verify(verificationKey, token, { footer })
  assertEqual(result.claims.sub, label, label + ' token round trip')

  if (operations.includes('PublicKeyID')) {
    assertEqual(
      await protocol.PublicKeyID(await protocol.ExportPublicKey(publicKey)),
      await protocol.PublicKeyID(publicSerialized),
      label + ' public-key identifier',
    )
    assertEqual(
      await protocol.SecretKeyID(await protocol.ExportSecretKey(secretKey)),
      await protocol.SecretKeyID(secretSerialized),
      label + ' secret-key identifier',
    )
  }

  const wrappingKey = await protocol.GenerateWrappingKey({ extractable: true })
  const wrappingMaterial = await protocol.ExportWrappingKey(wrappingKey)
  const importedWrappingKey = await protocol.ImportWrappingKey(wrappingMaterial, {
    extractable: true,
  })
  if (!equalBytes(await protocol.ExportWrappingKey(importedWrappingKey), wrappingMaterial)) {
    fail(label + ' wrapping-key round trip failed')
  }

  if (operations.includes('WrapSecretKey')) {
    const wrapped = await protocol.WrapSecretKey(secretKey, importedWrappingKey)
    const unwrapped = await protocol.UnwrapSecretKey(wrapped, importedWrappingKey, {
      extractable: true,
    })
    assertEqual(
      await protocol.ExportSecretKey(unwrapped),
      secretSerialized,
      label + ' PIE round trip',
    )

    const password = encoder.encode('artifact-smoke-password')
    const passwordWrapped = await protocol.WrapSecretKeyWithPassword(
      secretKey,
      password,
      { iterations: 1_000 },
    )
    const passwordUnwrapped = await protocol.UnwrapSecretKeyWithPassword(
      passwordWrapped,
      password,
      { maxIterations: 1_000, extractable: true },
    )
    assertEqual(
      await protocol.ExportSecretKey(passwordUnwrapped),
      secretSerialized,
      label + ' password round trip',
    )
  }
}

for (const descriptor of protocols) {
  await (descriptor.purpose === 'local' ? smokeLocal(descriptor) : smokePublic(descriptor))
}
`
}

function validateTarball(tarball, manifestDirectory, staging, checkTag = false) {
  const source = manifest(manifestDirectory)
  if (source.name !== 'paseto') throw new Error(`unsupported package: ${source.name}`)
  if (Object.keys(source.dependencies ?? {}).length !== 0) {
    throw new Error('paseto must not declare runtime dependencies')
  }

  const isolated = join(staging, 'installed')
  mkdirSync(isolated)
  writeFileSync(
    join(isolated, 'package.json'),
    JSON.stringify({ name: 'paseto-artifact-validation', private: true, type: 'module' }),
  )
  run(
    npm,
    [
      'install',
      '--install-strategy=hoisted',
      '--omit=dev',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      tarball,
    ],
    isolated,
  )

  const installed = join(isolated, 'node_modules', 'paseto')
  const packed = manifest(installed)
  if (packed.name !== source.name || packed.version !== source.version) {
    throw new Error('the tarball does not match the checked-out package name and version')
  }
  if (Object.keys(packed.dependencies ?? {}).length !== 0) {
    throw new Error('packed paseto must not declare runtime dependencies')
  }
  if (JSON.stringify(packed.exports) !== JSON.stringify(expectedExports())) {
    throw new Error('packed exports do not match the nine public entry points')
  }
  if (
    checkTag &&
    process.env.GITHUB_REF_NAME !== undefined &&
    process.env.GITHUB_REF_NAME !== `v${packed.version}`
  ) {
    throw new Error(
      `release tag ${process.env.GITHUB_REF_NAME} does not match ${packed.name}@${packed.version}`,
    )
  }

  const expectedFiles = expectedPackageFiles(manifestDirectory)
  const actualFiles = listPackageFiles(installed).sort()
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(
      `packed files differ\nexpected: ${expectedFiles.join(', ')}\nactual:   ${actualFiles.join(', ')}`,
    )
  }

  writeFileSync(join(isolated, 'smoke.mjs'), smokeTestSource())
  run(process.execPath, ['smoke.mjs'], isolated)
  console.log(
    `validated ${basename(tarball)} as ${packed.name}@${packed.version} containing ${actualFiles.join(', ')}`,
  )
}

const [suppliedTarball, suppliedManifestDirectory, ...extraArguments] = process.argv.slice(2)
if (extraArguments.length !== 0 || (suppliedManifestDirectory !== undefined && !suppliedTarball)) {
  throw new Error('expected a package tarball followed by its manifest directory')
}
const resolvedManifestDirectory = resolve(root, suppliedManifestDirectory ?? '.')

const staging = mkdtempSync(join(tmpdir(), 'paseto-dist-'))
try {
  if (suppliedTarball) {
    validateTarball(resolve(root, suppliedTarball), resolvedManifestDirectory, staging, true)
  } else {
    run(npm, ['run', 'build'])
    validateTarball(createTarball(staging), root, staging)
  }
} finally {
  rmSync(staging, { recursive: true, force: true })
}
