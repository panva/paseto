import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { build } from 'esbuild'
import ts from 'typescript'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

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
    path: 'v1/local',
    purpose: 'local',
    version: 1,
    factories: factoryNames(localLegacy),
    helpers: localCryptoKeyHelpers,
  },
  {
    path: 'v1/public',
    purpose: 'public',
    version: 1,
    factories: factoryNames(publicLegacy),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
  {
    path: 'v2/local',
    purpose: 'local',
    version: 2,
    factories: factoryNames(localModern),
    helpers: [],
  },
  {
    path: 'v2/public',
    purpose: 'public',
    version: 2,
    factories: factoryNames(publicModern),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
  {
    path: 'v3/local',
    purpose: 'local',
    version: 3,
    factories: factoryNames(localV3),
    helpers: localCryptoKeyHelpers,
  },
  {
    path: 'v3/public',
    purpose: 'public',
    version: 3,
    factories: factoryNames(publicLegacy),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
  {
    path: 'v4/local',
    purpose: 'local',
    version: 4,
    factories: factoryNames(localModern),
    helpers: [],
  },
  {
    path: 'v4/public',
    purpose: 'public',
    version: 4,
    factories: factoryNames(publicModern),
    helpers: [...publicCryptoKeyHelpers, ...secretCryptoKeyHelpers],
  },
]

const moduleFixtures = [
  { label: 'source', extension: 'ts' },
  { label: 'distribution', extension: 'js' },
]

function sourceFile(filename, kind) {
  const source = readFileSync(join(root, filename), 'utf8')
  return {
    filename,
    source,
    parsed: ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true, kind),
  }
}

function hasExportModifier(node) {
  return node.modifiers?.some(({ kind }) => kind === ts.SyntaxKind.ExportKeyword) === true
}

function runtimeExportNames(parsed) {
  const names = []
  for (const statement of parsed.statements) {
    if (!hasExportModifier(statement)) continue
    if (
      (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) &&
      statement.name !== undefined
    ) {
      names.push(statement.name.text)
    } else if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name)) names.push(declaration.name.text)
      }
    }
  }
  return names.sort()
}

function dependencySyntax(parsed) {
  let found
  function visit(node) {
    if (
      ts.isImportDeclaration(node) ||
      ts.isImportEqualsDeclaration(node) ||
      (ts.isExportDeclaration(node) && node.moduleSpecifier !== undefined) ||
      (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)
    ) {
      found = node
      return
    }
    ts.forEachChild(node, visit)
  }
  visit(parsed)
  return found
}

for (const extension of ['ts', 'js']) {
  const filename = `index.${extension}`
  if (!existsSync(join(root, filename))) {
    throw new Error(`${filename} is missing; run the build before checking tree-shaking`)
  }
  const file = sourceFile(filename, extension === 'ts' ? ts.ScriptKind.TS : ts.ScriptKind.JS)
  if (dependencySyntax(file.parsed) !== undefined) {
    throw new Error(`${filename} must remain a single flat module without imports or re-exports`)
  }
  if (/\bnode:|\brequire\s*\(/u.test(file.source)) {
    throw new Error(`${filename} must use runtime APIs and must not reference Node.js modules`)
  }
}

const packageJson = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
if (Object.keys(packageJson.dependencies ?? {}).length !== 0) {
  throw new Error('paseto must not declare runtime dependencies')
}

function collectRuntimeFiles(directory, extension, files) {
  if (!existsSync(directory)) return
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const filename = join(directory, entry.name)
    if (entry.isDirectory()) {
      collectRuntimeFiles(filename, extension, files)
    } else if (
      entry.isFile() &&
      filename.endsWith(`.${extension}`) &&
      !filename.endsWith(`.d.${extension}`)
    ) {
      files.push(filename)
    }
  }
}

function insideFunctionOrClass(node) {
  for (let parent = node.parent; parent !== undefined; parent = parent.parent) {
    if (
      ts.isFunctionDeclaration(parent) ||
      ts.isFunctionExpression(parent) ||
      ts.isArrowFunction(parent) ||
      ts.isMethodDeclaration(parent) ||
      ts.isConstructorDeclaration(parent) ||
      ts.isGetAccessorDeclaration(parent) ||
      ts.isSetAccessorDeclaration(parent) ||
      ts.isClassDeclaration(parent) ||
      ts.isClassExpression(parent)
    ) {
      return true
    }
  }
  return false
}

function checkPureAnnotations(filename, expectedCapabilities = []) {
  const kind = filename.endsWith('.ts') ? ts.ScriptKind.TS : ts.ScriptKind.JS
  const file = sourceFile(filename, kind)
  const expressions = []
  function visit(node) {
    if (ts.isCallExpression(node) || ts.isNewExpression(node)) expressions.push(node)
    ts.forEachChild(node, visit)
  }
  visit(file.parsed)
  expressions.sort((left, right) => left.getStart(file.parsed) - right.getStart(file.parsed))

  const annotated = new Set()
  for (const match of file.source.matchAll(/\/\*\s*@__PURE__\s*\*\//gu)) {
    const end = match.index + match[0].length
    const expression = expressions.find(
      (candidate) =>
        candidate.getStart(file.parsed) >= end &&
        /^\s*$/u.test(file.source.slice(end, candidate.getStart(file.parsed))),
    )
    if (expression === undefined) {
      throw new Error(
        `${filename}:${file.parsed.getLineAndCharacterOfPosition(match.index).line + 1} PURE annotation is not attached to a call`,
      )
    }
    if (insideFunctionOrClass(expression)) {
      throw new Error(
        `${filename}:${file.parsed.getLineAndCharacterOfPosition(match.index).line + 1} PURE annotation is not on a module-scope call`,
      )
    }
    annotated.add(expression)
  }

  const declarations = new Map()
  for (const statement of file.parsed.statements) {
    if (!hasExportModifier(statement) || !ts.isVariableStatement(statement)) continue
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name)) declarations.set(declaration.name.text, declaration)
    }
  }
  for (const name of expectedCapabilities) {
    const declaration = declarations.get(name)
    if (declaration === undefined || declaration.initializer === undefined) {
      throw new Error(`${filename} does not export ${name}`)
    }
    if (!ts.isCallExpression(declaration.initializer) || !annotated.has(declaration.initializer)) {
      throw new Error(`${filename} ${name} creator call must have a PURE annotation`)
    }
  }
}

for (const extension of ['ts', 'js']) {
  const runtimeFiles = [join(root, `index.${extension}`)]
  collectRuntimeFiles(join(root, '_internal'), extension, runtimeFiles)
  for (const filename of runtimeFiles) {
    checkPureAnnotations(filename.slice(root.length + 1))
  }
  for (const subpath of subpaths) {
    const filename = `${subpath.path}.${extension}`
    if (!existsSync(join(root, filename))) {
      throw new Error(`${filename} is missing; run the build before checking tree-shaking`)
    }
    const actual = runtimeExportNames(
      sourceFile(filename, extension === 'ts' ? ts.ScriptKind.TS : ts.ScriptKind.JS).parsed,
    )
    const expected = [...subpath.factories, ...subpath.helpers].sort()
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`${filename} runtime exports differ from its published API`)
    }
    checkPureAnnotations(filename, subpath.factories)
  }
}

const examples = []
collectRuntimeFiles(join(root, 'examples'), 'ts', examples)
collectRuntimeFiles(join(root, 'examples'), 'js', examples)
for (const filename of examples) {
  if (/\/\*\s*@__PURE__\s*\*\//u.test(readFileSync(filename, 'utf8'))) {
    throw new Error(`${filename.slice(root.length + 1)} must not contain PURE annotations`)
  }
}

async function bundle(contents, sourcefile, minify = false) {
  const result = await build({
    bundle: true,
    format: 'esm',
    legalComments: 'none',
    logLevel: 'silent',
    metafile: true,
    minify,
    platform: 'neutral',
    stdin: { contents, loader: 'ts', resolveDir: root, sourcefile },
    treeShaking: true,
    write: false,
  })
  return { output: result.outputFiles[0].text, metafile: result.metafile }
}

function assertContains(output, marker, name, description) {
  const present = typeof marker === 'string' ? output.includes(marker) : marker.test(output)
  if (!present) throw new Error(`${name} bundle does not contain ${description}`)
}

function assertAbsent(output, marker, name, description) {
  const present = typeof marker === 'string' ? output.includes(marker) : marker.test(output)
  if (present) throw new Error(`${name} bundle retained ${description}`)
}

function assertOnlyFacade(metafile, target, name) {
  const facades = Object.keys(metafile.inputs).filter((input) =>
    /(?:^|\/)v[1-4]\/(?:local|public)\.(?:ts|js)$/u.test(input),
  )
  if (facades.length !== 1 || !facades[0].endsWith(target)) {
    throw new Error(`${name} bundle included unexpected facades: ${facades.join(', ')}`)
  }
}

const familySymbols = [
  {
    version: 1,
    purpose: 'local',
    markers: [/\b(?:encrypt|decrypt)LocalV1\b/u, /\b(?:encrypt|decrypt)V1Local\b/u],
  },
  {
    version: 3,
    purpose: 'local',
    markers: [
      /\b(?:encrypt|decrypt)LocalV3\b/u,
      /\b(?:encrypt|decrypt)V3Local\b/u,
      /\b(?:generate|import|export|seal|unseal)\w*V3\b/u,
    ],
  },
  {
    version: 1,
    purpose: 'public',
    markers: [
      /\b(?:generatePublicKeyPair|signPublic|verifyPublic|importPublicKey|importSecretKey)V1\b/u,
      /\b(?:sign|verify)V1Public\b/u,
    ],
  },
  {
    version: 2,
    purpose: 'public',
    markers: [
      /\b(?:generatePublicKeyPair|signPublic|verifyPublic|importPublicKey|importSecretKey)V2\b/u,
      /\b(?:sign|verify)V2Public\b/u,
    ],
  },
  {
    version: 3,
    purpose: 'public',
    markers: [
      /\b(?:generatePublicKeyPair|signPublic|verifyPublic|importPublicKey|importSecretKey)V3\b/u,
      /\b(?:sign|verify)V3Public\b/u,
    ],
  },
  {
    version: 4,
    purpose: 'public',
    markers: [
      /\b(?:generatePublicKeyPair|signPublic|verifyPublic|importPublicKey|importSecretKey)V4\b/u,
      /\b(?:sign|verify)V4Public\b/u,
    ],
  },
]

const factoryFixtures = [
  {
    name: 'v3/local KeyID',
    path: 'v3/local',
    purpose: 'local',
    version: 3,
    imports: ['KeyID'],
    required: [/\blocalPaserkIdLegacy\b/u, /\bpaserkIdSha384\b/u],
    forbidden: [
      /\b(?:generate|import|export)LocalKey\b/u,
      /\b(?:encrypt|decrypt)LocalV3\b/u,
      /\b(?:wrap|unwrap)LocalKey/u,
      /\b(?:generate|import|export|seal|unseal)\w*Sealing/u,
      /\blocalKeyData\b/u,
      /\brequireExtractable\b/u,
      /\bLocalKeyImpl\b/u,
    ],
  },
  {
    name: 'v3/public PublicKeyID',
    path: 'v3/public',
    purpose: 'public',
    version: 3,
    imports: ['PublicKeyID'],
    required: [/\bpublicPaserkIdLegacy\b/u, /\bpaserkIdSha384\b/u],
    forbidden: [
      /\b(?:generatePublicKeyPairV3|signPublicV3|verifyPublicV3|importPublicKeyV3|exportPublicKey)\b/u,
      /\b(?:importSecretKeyV3|exportSecretKey)\b/u,
      /\bgetPublicKey\b/u,
      /\b(?:wrap|unwrap)SecretKey/u,
      /\bpublicKeyData\b/u,
      /\brequireExtractable\b/u,
      /\bPublicKeyImpl\b/u,
    ],
  },
  {
    name: 'v3/local Decrypt+ImportKey',
    path: 'v3/local',
    purpose: 'local',
    version: 3,
    imports: ['Decrypt', 'ImportKey'],
    required: [/\bdecryptLocalV3\b/u, /\bimportLocalKeyLegacy\b/u],
    forbidden: [
      /\bgenerateLocalKeyLegacy\b/u,
      /\bencryptLocalV3\b/u,
      /\bexportLocalKey\b/u,
      /\blocalPaserkIdLegacy\b/u,
      /\b(?:wrap|unwrap)LocalKey/u,
      /\b(?:generate|import|export|seal|unseal)\w*Sealing/u,
      /\bprepareClaims\b/u,
      'addIssuedAt',
      'expiresIn',
      'nonExpiring',
      'local-wrap.pie',
      'local-pw',
      "'seal'",
    ],
  },
  {
    name: 'v4/public GenerateKeyPair+Sign',
    path: 'v4/public',
    purpose: 'public',
    version: 4,
    imports: ['GenerateKeyPair', 'Sign'],
    required: [/\bgeneratePublicKeyPairV4\b/u, /\bsignPublicV4\b/u],
    forbidden: [
      /\bverifyPublicV4\b/u,
      /\bimport(?:Public|Secret)KeyV4\b/u,
      /\bexport(?:Public|Secret)Key\b/u,
      /\bgetPublicKey\b/u,
      /\b(?:public|secret)PaserkIdLegacy\b/u,
      /\b(?:wrap|unwrap)SecretKey/u,
      /\bpaserkHeader\b/u,
      /\bparsePaserk\b/u,
      /\bserializePaserk\b/u,
      /\bVerify\b/u,
      /\bImportPublicKey\b/u,
      /\bImportSecretKey\b/u,
    ],
  },
  {
    name: 'v3/local WrapKey',
    path: 'v3/local',
    purpose: 'local',
    version: 3,
    imports: ['WrapKey'],
    required: [/\bwrapLocalKeyLegacy\b/u, /\bwrapPieSha384\b/u, 'local-wrap.pie'],
    forbidden: [
      /\bunwrapLocalKeyLegacy\b/u,
      /\bunwrapPieSha384\b/u,
      /\b(?:wrap|unwrap)LocalKeyWithPassword/u,
      /\b(?:generate|import|export|seal|unseal)\w*Sealing/u,
      /\b(?:encrypt|decrypt)LocalV3\b/u,
      /\bprepareClaims\b/u,
      'local-pw',
      "'seal'",
      'v3.local.',
      /\bInspectFooter\b/u,
      'Malformed token',
      'token footer',
    ],
  },
]

const byteOnlyLocalFixtures = [2, 4].map((version) => ({
  name: `v${version}/local GenerateKey+ImportKey byte-only`,
  path: `v${version}/local`,
  purpose: 'local',
  version,
  imports: ['GenerateKey', 'ImportKey'],
  required: [
    /\blocalKeyFromMaterialModern\b/u,
    /\bgenerateLocalKeyModern\b/u,
    /\bimportLocalKeyModern\b/u,
  ],
  forbidden: [
    /\blocalKeyFromMaterialLegacy\b/u,
    /\bgenerateLocalKeyLegacy\b/u,
    /\bimportLocalKeyLegacy\b/u,
    /\bimportLocalCryptoKey\b/u,
    /\bassertLocalCryptoKey\b/u,
    /\blocalKeyFromCryptoKey\b/u,
    /\blocalKeyToCryptoKey\b/u,
    'HKDF',
  ],
}))

const adapterFixtures = subpaths.flatMap(({ path, purpose, version, helpers }) =>
  helpers.map((helper) => {
    const fromCryptoKey = helper.endsWith('FromCryptoKey')
    if (purpose === 'local') {
      return {
        name: `${path} ${helper}`,
        path,
        purpose,
        version,
        direct: true,
        imports: [helper],
        required: fromCryptoKey
          ? [/\blocalKeyFromCryptoKey\b/u, /\bassertLocalCryptoKey\b/u, /\bLocalKeyImpl\b/u]
          : [/\blocalKeyToCryptoKey\b/u, /\blocalKeyData\b/u],
        forbidden: fromCryptoKey
          ? [
              /\blocalKeyToCryptoKey\b/u,
              /\bsecretKeyFromCryptoKey\b/u,
              /\b(?:encrypt|decrypt)(?:LocalV[1-4]|V[1-4]Local)\b/u,
              /\b(?:wrap|unwrap)LocalKey/u,
              /\bcreateOperation\b/u,
              'paseto-encryption-key',
              'local-wrap.pie',
              'local-pw',
            ]
          : [
              /\blocalKeyFromCryptoKey\b/u,
              /\bassertLocalCryptoKey\b/u,
              /\bLocalKeyImpl\b/u,
              /\bcopyBytes\b/u,
              /\bcreateOperation\b/u,
              "'HKDF'",
            ],
      }
    }

    const requiredAlgorithm =
      version === 1 ? ['RSA-PSS', 'SHA-384'] : version === 3 ? ['ECDSA', 'P-384'] : ['Ed25519']
    const unrelatedAlgorithms =
      version === 1
        ? ['Ed25519', 'ECDSA', /\bcompressP384\b/u]
        : version === 3
          ? ['RSA-PSS', 'Ed25519', /\brsaPrivatePkcs1\b/u]
          : ['RSA-PSS', 'ECDSA', /\brsaPrivatePkcs1\b/u, /\bcompressP384\b/u]

    if (helper.startsWith('PublicKey')) {
      return {
        name: `${path} ${helper}`,
        path,
        purpose,
        version,
        direct: true,
        imports: [helper],
        required: fromCryptoKey
          ? [/\bPublicKeyImpl\b/u, ...requiredAlgorithm]
          : [/\bpublicKeyToCryptoKey\b/u, /\bpublicKeyData\b/u],
        forbidden: fromCryptoKey
          ? [
              /\bpublicKeyToCryptoKey\b/u,
              /\b(?:secretKeyFromCryptoKey|secretKeyToCryptoKey)\w*\b/u,
              /\bSecretKeyImpl\b/u,
              /\bgetPublicCryptoKey\b/u,
              /\brsaPrivatePkcs1\b/u,
              /\b(?:sign|verify)V[1-4]Public\b/u,
              /\bcreateOperation\b/u,
              'secret-wrap.pie',
              'secret-pw',
              ...unrelatedAlgorithms,
            ]
          : [
              /\bpublicKeyFromCryptoKey\w*\b/u,
              /\b(?:secretKeyFromCryptoKey|secretKeyToCryptoKey)\w*\b/u,
              /\bPublicKeyImpl\b/u,
              /\bSecretKeyImpl\b/u,
              /\bgetPublicCryptoKey\b/u,
              /\bcopyBytes\b/u,
              /\bcreateOperation\b/u,
              'RSA-PSS',
              'Ed25519',
              'ECDSA',
            ],
      }
    }

    return {
      name: `${path} ${helper}`,
      path,
      purpose,
      version,
      direct: true,
      imports: [helper],
      required: fromCryptoKey
        ? [/\bSecretKeyImpl\b/u, /\bgetPublicCryptoKey\b/u, ...requiredAlgorithm]
        : [/\bsecretKeyToCryptoKey\b/u, /\bsecretKeyData\b/u],
      forbidden: fromCryptoKey
        ? [
            /\bsecretKeyToCryptoKey\b/u,
            /\b(?:publicKeyFromCryptoKey|publicKeyToCryptoKey)\w*\b/u,
            /\bPublicKeyImpl\b/u,
            /\b(?:sign|verify)V[1-4]Public\b/u,
            /\bcreateOperation\b/u,
            'secret-wrap.pie',
            'secret-pw',
            ...unrelatedAlgorithms,
          ]
        : [
            /\bsecretKeyFromCryptoKey\b/u,
            /\b(?:publicKeyFromCryptoKey|publicKeyToCryptoKey)\w*\b/u,
            /\bPublicKeyImpl\b/u,
            /\bassertSecretCryptoKey\b/u,
            /\bSecretKeyImpl\b/u,
            /\bgetPublicCryptoKey\b/u,
            /\bcreateOperation\b/u,
            'RSA-PSS',
            'Ed25519',
            'ECDSA',
          ],
    }
  }),
)

const deepFixtures = [...factoryFixtures, ...byteOnlyLocalFixtures, ...adapterFixtures]

function fixtureEntry(fixture, extension) {
  if (fixture.direct) {
    const imports = fixture.imports.join(', ')
    return `import { ${imports} } from './${fixture.path}.${extension}'\nglobalThis.__pasetoTreeShakingResult = ${imports}\n`
  }
  const imports = factoryNames(fixture.imports).join(', ')
  const constructor = fixture.purpose === 'local' ? 'LocalProtocol' : 'PublicProtocol'
  return `import { ${constructor} } from './index.${extension}'\nimport { ${imports} } from './${fixture.path}.${extension}'\nglobalThis.__pasetoTreeShakingResult = new ${constructor}(${imports})\n`
}

const deepResults = await Promise.all(
  moduleFixtures.flatMap((moduleFixture) =>
    deepFixtures.map(async (fixture) => {
      const name = `${moduleFixture.label} ${fixture.name}`
      const contents = fixtureEntry(fixture, moduleFixture.extension)
      const [readable, minified] = await Promise.all([
        bundle(contents, `${name}.ts`),
        bundle(contents, `${name}.min.ts`, true),
      ])
      return { ...fixture, ...moduleFixture, name, readable, minified }
    }),
  ),
)

for (const fixture of deepResults) {
  assertOnlyFacade(fixture.readable.metafile, `${fixture.path}.${fixture.extension}`, fixture.name)
  for (const marker of fixture.required) {
    assertContains(fixture.readable.output, marker, fixture.name, String(marker))
  }
  for (const marker of fixture.forbidden) {
    assertAbsent(fixture.readable.output, marker, fixture.name, String(marker))
  }
  for (const family of familySymbols) {
    if (family.version === fixture.version && family.purpose === fixture.purpose) continue
    for (const marker of family.markers) {
      assertAbsent(
        fixture.readable.output,
        marker,
        fixture.name,
        `v${family.version}/${family.purpose} implementation`,
      )
    }
  }
}

const rootExports = runtimeExportNames(sourceFile('index.ts', ts.ScriptKind.TS).parsed)

async function bundleEveryNamedExport({ label, extension }) {
  const virtualModules = new Map()
  const entryPoints = {}
  const entries = []
  const modules = [
    { path: 'index', exports: rootExports },
    ...subpaths.map(({ path, factories, helpers }) => ({
      path,
      exports: [...factories, ...helpers],
    })),
  ]
  let index = 0
  for (const module of modules) {
    for (const name of module.exports) {
      const key = `entry-${index++}`
      const virtual = `paseto-fixture:${key}`
      virtualModules.set(
        virtual,
        `import { ${name} } from './${module.path}.${extension}'\nglobalThis[${JSON.stringify(`__paseto_${name}`)}] = ${name}\n`,
      )
      entryPoints[key] = virtual
      entries.push({ key, name, path: module.path })
    }
  }

  const result = await build({
    bundle: true,
    entryNames: '[name]',
    entryPoints,
    format: 'esm',
    legalComments: 'none',
    logLevel: 'silent',
    metafile: true,
    outdir: join(root, '.tree-shaking'),
    platform: 'neutral',
    plugins: [
      {
        name: 'paseto-tree-shaking-fixtures',
        setup(build) {
          build.onResolve({ filter: /^paseto-fixture:/ }, ({ path }) => ({
            path,
            namespace: 'paseto-fixture',
          }))
          build.onLoad({ filter: /.*/, namespace: 'paseto-fixture' }, ({ path }) => ({
            contents: virtualModules.get(path),
            loader: 'ts',
            resolveDir: root,
          }))
        },
      },
    ],
    treeShaking: true,
    write: false,
  })

  const outputs = new Map(result.outputFiles.map((file) => [basename(file.path, '.js'), file.text]))
  for (const entry of entries) {
    const output = outputs.get(entry.key)
    if (output === undefined) throw new Error(`${label} ${entry.path} ${entry.name} did not bundle`)
    assertContains(output, `__paseto_${entry.name}`, `${label} ${entry.path}`, entry.name)
    if (entry.path !== 'index') {
      const outputMetadata = Object.entries(result.metafile.outputs).find(([filename]) =>
        filename.endsWith(`/${entry.key}.js`),
      )?.[1]
      if (outputMetadata === undefined) throw new Error(`missing metadata for ${entry.key}`)
      const facades = Object.keys(outputMetadata.inputs).filter((input) =>
        /(?:^|\/)v[1-4]\/(?:local|public)\.(?:ts|js)$/u.test(input),
      )
      if (facades.length !== 1 || !facades[0].endsWith(`${entry.path}.${extension}`)) {
        throw new Error(`${label} ${entry.path} ${entry.name} included ${facades.join(', ')}`)
      }
    }
  }
  return entries.length
}

const namedExportCounts = await Promise.all(moduleFixtures.map(bundleEveryNamedExport))

const paeSizes = []
for (const moduleFixture of moduleFixtures) {
  const contents = `import { PAE } from './index.${moduleFixture.extension}'\nglobalThis.__pasetoTreeShakingResult = PAE\n`
  const result = await bundle(contents, `${moduleFixture.label}-pae.ts`, true)
  if (result.output.length > 1_000) {
    throw new Error(
      `${moduleFixture.label} PAE-only bundle is unexpectedly large (${result.output.length} bytes)`,
    )
  }
  assertAbsent(
    result.output,
    'WeakSet',
    `${moduleFixture.label} PAE-only`,
    'capability factory registry',
  )
  paeSizes.push(`${moduleFixture.label} PAE-only ${result.output.length} bytes`)
}

const deepSizes = deepResults
  .map(({ name, minified }) => `${name} ${minified.output.length} bytes`)
  .join(', ')
console.log(
  `tree-shaking OK: ${paeSizes.join(', ')}; ${namedExportCounts[0]} source and ${namedExportCounts[1]} distribution named exports bundled; ${deepSizes}`,
)
