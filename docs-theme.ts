import {
  ConditionalType,
  DeclarationReflection,
  IntersectionType,
  LiteralType,
  ReferenceType,
  ReflectionKind,
  ReflectionType,
  TupleType,
  UnionType,
  type Application,
  type SomeType,
} from 'typedoc'
import {
  MarkdownTheme,
  MarkdownThemeContext,
  type MarkdownPageEvent,
} from 'typedoc-plugin-markdown'

type FactorySignature = (version: string) => string

interface FactoryPage {
  readonly version: string
  readonly purpose: 'local' | 'public'
  readonly factory: string
  readonly operation: string
}

interface CreatorOperation {
  readonly operation: string
  readonly signature: string
}

const localFactorySignatures: Readonly<Record<string, FactorySignature>> = {
  GenerateKeyFactory: () => 'GenerateKey(options?: KeyOptions): Promise<LocalKey>',
  EncryptFactory: (version) =>
    `Encrypt<C extends object>(key: LocalKey, claims: C, options?: ProduceOptions<${version}>): Promise<string>`,
  DecryptFactory: (version) =>
    `Decrypt(key: LocalKey, token: string, options?: ConsumeOptions<${version}>): Promise<TokenResult>`,
  ImportKeyFactory: (version) =>
    `ImportKey(paserk: LocalPASERK<${version}>, options?: KeyOptions): Promise<LocalKey>`,
  ExportKeyFactory: (version) => `ExportKey(key: LocalKey): Promise<LocalPASERK<${version}>>`,
  KeyIDFactory: (version) =>
    `KeyID(paserk: LocalKeyIDInput<${version}>): Promise<LocalIdPASERK<${version}>>`,
  GenerateWrappingKeyFactory: () =>
    'GenerateWrappingKey(options?: KeyOptions): Promise<WrappingKey>',
  ImportWrappingKeyFactory: () =>
    'ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<WrappingKey>',
  ExportWrappingKeyFactory: () => 'ExportWrappingKey(key: WrappingKey): Promise<Uint8Array>',
  WrapKeyFactory: (version) =>
    `WrapKey(key: LocalKey, wrappingKey: WrappingKey): Promise<WrappedLocalPASERK<${version}, 'pie'>>`,
  UnwrapKeyFactory: (version) =>
    `UnwrapKey(paserk: WrappedLocalPASERK<${version}, 'pie'>, wrappingKey: WrappingKey, options?: KeyOptions): Promise<LocalKey>`,
  WrapKeyWithPasswordFactory: (version) =>
    `WrapKeyWithPassword(key: LocalKey, password: Uint8Array, options?: PasswordWrapOptions<${version}>): Promise<PasswordWrappedLocalPASERK<${version}>>`,
  UnwrapKeyWithPasswordFactory: (version) =>
    `UnwrapKeyWithPassword(paserk: PasswordWrappedLocalPASERK<${version}>, password: Uint8Array, options?: PasswordUnwrapOptions<${version}>): Promise<LocalKey>`,
  GenerateSealingKeyPairFactory: () =>
    'GenerateSealingKeyPair(options?: KeyOptions): Promise<KeyPair<SealingPublicKey, SealingSecretKey>>',
  ImportSealingPublicKeyFactory: () =>
    'ImportSealingPublicKey(material: Uint8Array): Promise<SealingPublicKey>',
  ImportSealingSecretKeyFactory: () =>
    'ImportSealingSecretKey(material: Uint8Array, options?: KeyOptions): Promise<SealingSecretKey>',
  ExportSealingPublicKeyFactory: () =>
    'ExportSealingPublicKey(key: SealingPublicKey): Promise<Uint8Array>',
  ExportSealingSecretKeyFactory: () =>
    'ExportSealingSecretKey(key: SealingSecretKey): Promise<Uint8Array>',
  SealKeyFactory: (version) =>
    `SealKey(key: LocalKey, recipient: SealingPublicKey): Promise<SealedLocalPASERK<${version}>>`,
  UnsealKeyFactory: (version) =>
    `UnsealKey(paserk: SealedLocalPASERK<${version}>, recipient: SealingSecretKey, options?: KeyOptions): Promise<LocalKey>`,
}

const publicFactorySignatures: Readonly<Record<string, FactorySignature>> = {
  GenerateKeyPairFactory: () =>
    'GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<PublicKey, SecretKey>>',
  SignFactory: (version) =>
    `Sign<C extends object>(key: SecretKey, claims: C, options?: ProduceOptions<${version}>): Promise<string>`,
  VerifyFactory: (version) =>
    `Verify(key: PublicKey, token: string, options?: ConsumeOptions<${version}>): Promise<TokenResult>`,
  ImportPublicKeyFactory: (version) =>
    `ImportPublicKey(paserk: PublicPASERK<${version}>): Promise<PublicKey>`,
  ExportPublicKeyFactory: (version) =>
    `ExportPublicKey(key: PublicKey): Promise<PublicPASERK<${version}>>`,
  ImportSecretKeyFactory: (version) =>
    `ImportSecretKey(paserk: SecretPASERK<${version}>, options?: KeyOptions): Promise<SecretKey>`,
  ExportSecretKeyFactory: (version) =>
    `ExportSecretKey(key: SecretKey): Promise<SecretPASERK<${version}>>`,
  GetPublicKeyFactory: () => 'GetPublicKey(key: SecretKey): Promise<PublicKey>',
  PublicKeyIDFactory: (version) =>
    `PublicKeyID(paserk: PublicPASERK<${version}>): Promise<PublicIdPASERK<${version}>>`,
  SecretKeyIDFactory: (version) =>
    `SecretKeyID(paserk: SecretKeyIDInput<${version}>): Promise<SecretIdPASERK<${version}>>`,
  GenerateWrappingKeyFactory: () =>
    'GenerateWrappingKey(options?: KeyOptions): Promise<WrappingKey>',
  ImportWrappingKeyFactory: () =>
    'ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<WrappingKey>',
  ExportWrappingKeyFactory: () => 'ExportWrappingKey(key: WrappingKey): Promise<Uint8Array>',
  WrapSecretKeyFactory: (version) =>
    `WrapSecretKey(key: SecretKey, wrappingKey: WrappingKey): Promise<WrappedSecretPASERK<${version}, 'pie'>>`,
  UnwrapSecretKeyFactory: (version) =>
    `UnwrapSecretKey(paserk: WrappedSecretPASERK<${version}, 'pie'>, wrappingKey: WrappingKey, options?: KeyOptions): Promise<SecretKey>`,
  WrapSecretKeyWithPasswordFactory: (version) =>
    `WrapSecretKeyWithPassword(key: SecretKey, password: Uint8Array, options?: PasswordWrapOptions<${version}>): Promise<PasswordWrappedSecretPASERK<${version}>>`,
  UnwrapSecretKeyWithPasswordFactory: (version) =>
    `UnwrapSecretKeyWithPassword(paserk: PasswordWrappedSecretPASERK<${version}>, password: Uint8Array, options?: PasswordUnwrapOptions<${version}>): Promise<SecretKey>`,
}

const creatorOperations: Readonly<Record<string, CreatorOperation>> = {
  LocalGenerateKey: {
    operation: 'GenerateKey',
    signature: 'GenerateKey(options?: KeyOptions): Promise<L>',
  },
  LocalEncrypt: {
    operation: 'Encrypt',
    signature:
      'Encrypt<C extends object>(key: L, claims: C, options?: ProduceOptions<V>): Promise<string>',
  },
  LocalDecrypt: {
    operation: 'Decrypt',
    signature: 'Decrypt(key: L, token: string, options?: ConsumeOptions<V>): Promise<TokenResult>',
  },
  LocalImportKey: {
    operation: 'ImportKey',
    signature: 'ImportKey(paserk: LocalPASERK<V>, options?: KeyOptions): Promise<L>',
  },
  LocalExportKey: {
    operation: 'ExportKey',
    signature: 'ExportKey(key: L): Promise<LocalPASERK<V>>',
  },
  LocalKeyID: {
    operation: 'KeyID',
    signature: 'KeyID(paserk: LocalKeyIDInput<V>): Promise<LocalIdPASERK<V>>',
  },
  LocalGenerateWrappingKey: {
    operation: 'GenerateWrappingKey',
    signature: 'GenerateWrappingKey(options?: KeyOptions): Promise<W>',
  },
  LocalImportWrappingKey: {
    operation: 'ImportWrappingKey',
    signature: 'ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<W>',
  },
  LocalExportWrappingKey: {
    operation: 'ExportWrappingKey',
    signature: 'ExportWrappingKey(key: W): Promise<Uint8Array>',
  },
  LocalWrapKey: {
    operation: 'WrapKey',
    signature: 'WrapKey(key: L, wrappingKey: W): Promise<WrappedLocalPASERK<V, Prefix>>',
  },
  LocalUnwrapKey: {
    operation: 'UnwrapKey',
    signature:
      'UnwrapKey(paserk: WrappedLocalPASERK<V, Prefix>, wrappingKey: W, options?: KeyOptions): Promise<L>',
  },
  LocalWrapKeyWithPassword: {
    operation: 'WrapKeyWithPassword',
    signature:
      'WrapKeyWithPassword(key: L, password: Uint8Array, options?: PasswordWrapOptions<V>): Promise<PasswordWrappedLocalPASERK<V>>',
  },
  LocalUnwrapKeyWithPassword: {
    operation: 'UnwrapKeyWithPassword',
    signature:
      'UnwrapKeyWithPassword(paserk: PasswordWrappedLocalPASERK<V>, password: Uint8Array, options?: PasswordUnwrapOptions<V>): Promise<L>',
  },
  LocalGenerateSealingKeyPair: {
    operation: 'GenerateSealingKeyPair',
    signature: 'GenerateSealingKeyPair(options?: KeyOptions): Promise<KeyPair<SP, SS>>',
  },
  LocalImportSealingPublicKey: {
    operation: 'ImportSealingPublicKey',
    signature: 'ImportSealingPublicKey(material: Uint8Array): Promise<SP>',
  },
  LocalImportSealingSecretKey: {
    operation: 'ImportSealingSecretKey',
    signature: 'ImportSealingSecretKey(material: Uint8Array, options?: KeyOptions): Promise<SS>',
  },
  LocalExportSealingPublicKey: {
    operation: 'ExportSealingPublicKey',
    signature: 'ExportSealingPublicKey(key: SP): Promise<Uint8Array>',
  },
  LocalExportSealingSecretKey: {
    operation: 'ExportSealingSecretKey',
    signature: 'ExportSealingSecretKey(key: SS): Promise<Uint8Array>',
  },
  LocalSealKey: {
    operation: 'SealKey',
    signature: 'SealKey(key: L, recipient: SP): Promise<SealedLocalPASERK<V>>',
  },
  LocalUnsealKey: {
    operation: 'UnsealKey',
    signature:
      'UnsealKey(paserk: SealedLocalPASERK<V>, recipient: SS, options?: KeyOptions): Promise<L>',
  },
  PublicGenerateKeyPair: {
    operation: 'GenerateKeyPair',
    signature: 'GenerateKeyPair(options?: KeyOptions): Promise<KeyPair<P, S>>',
  },
  PublicSign: {
    operation: 'Sign',
    signature:
      'Sign<C extends object>(key: S, claims: C, options?: ProduceOptions<V>): Promise<string>',
  },
  PublicVerify: {
    operation: 'Verify',
    signature: 'Verify(key: P, token: string, options?: ConsumeOptions<V>): Promise<TokenResult>',
  },
  PublicImportPublicKey: {
    operation: 'ImportPublicKey',
    signature: 'ImportPublicKey(paserk: PublicPASERK<V>): Promise<P>',
  },
  PublicExportPublicKey: {
    operation: 'ExportPublicKey',
    signature: 'ExportPublicKey(key: P): Promise<PublicPASERK<V>>',
  },
  PublicImportSecretKey: {
    operation: 'ImportSecretKey',
    signature: 'ImportSecretKey(paserk: SecretPASERK<V>, options?: KeyOptions): Promise<S>',
  },
  PublicExportSecretKey: {
    operation: 'ExportSecretKey',
    signature: 'ExportSecretKey(key: S): Promise<SecretPASERK<V>>',
  },
  PublicGetPublicKey: { operation: 'GetPublicKey', signature: 'GetPublicKey(key: S): Promise<P>' },
  PublicKeyID: {
    operation: 'PublicKeyID',
    signature: 'PublicKeyID(paserk: PublicPASERK<V>): Promise<PublicIdPASERK<V>>',
  },
  SecretKeyID: {
    operation: 'SecretKeyID',
    signature: 'SecretKeyID(paserk: SecretKeyIDInput<V>): Promise<SecretIdPASERK<V>>',
  },
  PublicGenerateWrappingKey: {
    operation: 'GenerateWrappingKey',
    signature: 'GenerateWrappingKey(options?: KeyOptions): Promise<W>',
  },
  PublicImportWrappingKey: {
    operation: 'ImportWrappingKey',
    signature: 'ImportWrappingKey(material: Uint8Array, options?: KeyOptions): Promise<W>',
  },
  PublicExportWrappingKey: {
    operation: 'ExportWrappingKey',
    signature: 'ExportWrappingKey(key: W): Promise<Uint8Array>',
  },
  PublicWrapSecretKey: {
    operation: 'WrapSecretKey',
    signature: 'WrapSecretKey(key: S, wrappingKey: W): Promise<WrappedSecretPASERK<V, Prefix>>',
  },
  PublicUnwrapSecretKey: {
    operation: 'UnwrapSecretKey',
    signature:
      'UnwrapSecretKey(paserk: WrappedSecretPASERK<V, Prefix>, wrappingKey: W, options?: KeyOptions): Promise<S>',
  },
  PublicWrapSecretKeyWithPassword: {
    operation: 'WrapSecretKeyWithPassword',
    signature:
      'WrapSecretKeyWithPassword(key: S, password: Uint8Array, options?: PasswordWrapOptions<V>): Promise<PasswordWrappedSecretPASERK<V>>',
  },
  PublicUnwrapSecretKeyWithPassword: {
    operation: 'UnwrapSecretKeyWithPassword',
    signature:
      'UnwrapSecretKeyWithPassword(paserk: PasswordWrappedSecretPASERK<V>, password: Uint8Array, options?: PasswordUnwrapOptions<V>): Promise<S>',
  },
}

function versionLiterals(type: SomeType): number[] {
  if (type instanceof LiteralType && typeof type.value === 'number') return [type.value]
  if (type instanceof TupleType || type instanceof UnionType) {
    const types = type instanceof TupleType ? type.elements : type.types
    return types.flatMap(versionLiterals)
  }
  return []
}

interface ConditionalProperties {
  readonly versions: readonly number[]
  readonly declaration: DeclarationReflection
}

function visibleConditionalChildren(declaration: DeclarationReflection) {
  return (declaration.children ?? []).filter(
    (child) => child.type?.type !== 'intrinsic' || child.type.name !== 'never',
  )
}

function collectConditionalProperties(
  type: SomeType | undefined,
  output: ConditionalProperties[],
  visited: Set<number>,
): void {
  if (type instanceof ConditionalType) {
    const versions = versionLiterals(type.extendsType)
    collectConditionalBranch(type.trueType, versions, output, visited)
    if (type.falseType instanceof ConditionalType) {
      collectConditionalProperties(type.falseType, output, visited)
    } else {
      const otherVersions = [1, 2, 3, 4].filter((version) => !versions.includes(version))
      collectConditionalBranch(type.falseType, otherVersions, output, visited)
    }
    return
  }
  if (type instanceof IntersectionType || type instanceof UnionType) {
    for (const child of type.types) collectConditionalProperties(child, output, visited)
    return
  }
  if (type instanceof ReferenceType) {
    const reflection = type.reflection
    if (
      reflection instanceof DeclarationReflection &&
      reflection.kind === ReflectionKind.TypeAlias &&
      !visited.has(reflection.id)
    ) {
      visited.add(reflection.id)
      collectConditionalProperties(reflection.type, output, visited)
    }
  }
}

function collectConditionalBranch(
  type: SomeType,
  versions: readonly number[],
  output: ConditionalProperties[],
  visited: Set<number>,
): void {
  if (type instanceof ReflectionType && visibleConditionalChildren(type.declaration).length) {
    output.push({ versions, declaration: type.declaration })
    return
  }
  collectConditionalProperties(type, output, visited)
}

function renderConditionalProperties(
  context: MarkdownThemeContext,
  model: DeclarationReflection,
  headingLevel: number,
): string {
  if (model.kind !== ReflectionKind.TypeAlias || !/(?:Options|Limits)$/u.test(model.name)) return ''
  const properties: ConditionalProperties[] = []
  collectConditionalProperties(model.type, properties, new Set([model.id]))
  if (properties.length === 0) return ''
  const heading = (offset: number, title: string) => `${'#'.repeat(headingLevel + offset)} ${title}`
  const sections = properties.map(({ versions, declaration }) => {
    const label =
      versions.length === 1 ? `Version ${versions[0]}` : `Versions ${versions.join(' and ')}`
    const children = declaration.children
    declaration.children = visibleConditionalChildren(declaration)
    try {
      return [
        heading(1, label),
        context.partials.typeDeclaration(declaration, { headingLevel: headingLevel + 1 }),
      ].join('\n\n')
    } finally {
      declaration.children = children
    }
  })
  return [heading(0, 'Version-specific Properties'), ...sections].join('\n\n')
}

function factoryPage(page: MarkdownPageEvent): FactoryPage | undefined {
  const match = /^v([1-4])\/(local|public)\/variables\/([^/]+)\.md$/u.exec(page.url)
  if (!match) return undefined
  const [, version, purpose, factory] = match
  if (!factory!.endsWith('Factory')) return undefined
  return {
    version: version!,
    purpose: purpose as FactoryPage['purpose'],
    factory: factory!,
    operation: factory!.slice(0, -'Factory'.length),
  }
}

function creatorOperation(page: MarkdownPageEvent): CreatorOperation | undefined {
  const match = /^paseto\/functions\/([^/]+)\.md$/u.exec(page.url)
  return match === null ? undefined : creatorOperations[match[1]!]
}

function installedOperation(page: MarkdownPageEvent): string {
  const details = factoryPage(page)
  let operation: string
  let signature: string | undefined
  let introduction: string
  if (details) {
    const signatures =
      details.purpose === 'local' ? localFactorySignatures : publicFactorySignatures
    operation = details.operation
    signature = signatures[details.factory]?.(details.version)
    introduction = 'Composing this factory installs the following protocol method.'
  } else {
    const creator = creatorOperation(page)
    if (!creator) return ''
    operation = creator.operation
    signature = creator.signature
    introduction = 'The returned capability factory installs the following protocol method.'
  }
  if (!signature) return ''
  const output = ['## Installed Operation', introduction, `\`\`\`text\n${signature}\n\`\`\``]
  if (operation === 'Encrypt' || operation === 'Sign') {
    output.push(
      '`C` must be a JSON-compatible claims object. Registered PASETO claims use string values.',
    )
  }
  return output.join('\n\n')
}

function protocolInstanceDescription(page: MarkdownPageEvent): string {
  const match = /^paseto\/type-aliases\/(Local|Public)ProtocolInstance\.md$/u.exec(page.url)
  if (!match) return ''
  return [
    '## Resulting Methods',
    'Each selected factory contributes one method named after its operation. The method retains the parameter and return types carried by that factory.',
  ].join('\n\n')
}

class PasetoMarkdownTheme extends MarkdownTheme {
  // @ts-ignore TypeDoc does not expose a stable render-context override signature.
  getRenderContext(page) {
    const context = new MarkdownThemeContext(this, page, this.application.options)
    const typeArguments = context.partials.typeArguments
    context.partials.typeArguments = function (values, options) {
      // @ts-ignore TypeDoc's render model types are not part of the stable theme API.
      if (values[0]?.name === 'ArrayBufferLike') return ''
      return typeArguments.call(this, values, options)
    }
    const reflectionType = context.partials.reflectionType
    context.partials.reflectionType = function (model, options) {
      const signatures = model.declaration.signatures
      if (signatures?.length === 1 && signatures[0]?.kind === ReflectionKind.ConstructorSignature) {
        return `new ${context.partials.functionType(signatures)}`
      }
      return reflectionType.call(this, model, options)
    }
    const someType = context.partials.someType
    context.partials.someType = function (model, options) {
      if (
        model instanceof IntersectionType &&
        model.types[0]?.type === 'reference' &&
        model.types[0].name === 'F' &&
        model.types
          .slice(1)
          .every(
            (type) =>
              type instanceof ReflectionType &&
              !type.declaration.children?.length &&
              !type.declaration.signatures?.length,
          )
      ) {
        return someType.call(this, model.types[0], options)
      }
      return someType.call(this, model, options)
    }
    const declaration = context.partials.declaration
    context.partials.declaration = function (model, options) {
      const rendered = declaration.call(this, model, options)
      const conditional = renderConditionalProperties(context, model, options?.headingLevel ?? 2)
      if (!conditional) return rendered
      const marker = '\n\n## Type Parameters'
      const position = rendered.indexOf(marker)
      if (position === -1) return `${rendered}\n\n${conditional}`
      return `${rendered.slice(0, position)}\n\n${conditional}${rendered.slice(position)}`
    }
    const declarationTitle = context.partials.declarationTitle
    context.partials.declarationTitle = function (model) {
      const details = factoryPage(page)
      if (details && model.kind === ReflectionKind.Variable && model.name === details.factory) {
        return `> \`const\` **${details.factory}**: \`CapabilityFactory\`<\`"${details.purpose}"\`, \`${details.version}\`, \`"${details.operation}"\`, installed operation below>`
      }
      if (model.kind === ReflectionKind.TypeAlias && model.name === 'LocalProtocolInstance') {
        return '> **LocalProtocolInstance**<`F`> = readonly local operation methods selected by `F`'
      }
      if (model.kind === ReflectionKind.TypeAlias && model.name === 'PublicProtocolInstance') {
        return '> **PublicProtocolInstance**<`F`> = readonly public operation methods selected by `F`'
      }
      return declarationTitle.call(this, model)
    }
    const sources = context.partials.sources
    context.partials.sources = function (...args) {
      const source = sources.call(this, args[0])
      return `[source]${source.slice(source.indexOf(']') + 1)}`
    }
    return context
  }

  render(page: MarkdownPageEvent): string {
    let output = super
      .render(page)
      .replaceAll(
        `## Constructors

### Constructor`,
        '## Constructor',
      )
      .replaceAll('\\| `string` & \\{ \\}', '')
      .replaceAll('\\| `string` & `object`', '')
      .replaceAll('`string` & \\{ \\} \\| ', '')
      .replaceAll('`string` & `object` \\| ', '')
      .replaceAll(`\\|`, '∣')
    const additions = [installedOperation(page), protocolInstanceDescription(page)].filter(Boolean)
    if (additions.length) output += `\n\n${additions.join('\n\n')}`
    return output
  }
}

export function load(app: Application) {
  app.renderer.defineTheme('my-markdown', PasetoMarkdownTheme)
}
