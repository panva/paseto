// Type-level regression tests. Nothing here runs; tsc compiling this file is the assertion.
import * as PASETO from 'paseto'
import {
  DecryptFactory as V3DecryptFactory,
  ExportKeyFactory as V3ExportKeyFactory,
  ExportSealingSecretKeyFactory as V3ExportSealingSecretKeyFactory,
  ExportWrappingKeyFactory as V3ExportWrappingKeyFactory,
  GenerateKeyFactory as V3GenerateKeyFactory,
  GenerateSealingKeyPairFactory as V3GenerateSealingKeyPairFactory,
  GenerateWrappingKeyFactory as V3GenerateWrappingKeyFactory,
  ImportKeyFactory as V3ImportKeyFactory,
  ImportSealingSecretKeyFactory as V3ImportSealingSecretKeyFactory,
  ImportWrappingKeyFactory as V3ImportWrappingKeyFactory,
  KeyIDFactory as V3KeyIDFactory,
  LocalKeyFromCryptoKey as V3LocalKeyFromCryptoKey,
  LocalKeyToCryptoKey as V3LocalKeyToCryptoKey,
  type LocalKey as V3LocalKey,
  type SealingPublicKey as V3SealingPublicKey,
  type SealingSecretKey as V3SealingSecretKey,
  UnwrapKeyWithPasswordFactory as V3UnwrapKeyWithPasswordFactory,
  WrapKeyFactory as V3WrapKeyFactory,
  type WrappingKey as V3WrappingKey,
} from 'paseto/v3/local'
import {
  ExportKeyFactory as V4ExportKeyFactory,
  GenerateKeyFactory as V4GenerateKeyFactory,
  ImportKeyFactory as V4ImportKeyFactory,
  type LocalKey as V4LocalKey,
} from 'paseto/v4/local'
import { SignFactory as V2SignFactory, type SecretKey as V2SecretKey } from 'paseto/v2/public'
import {
  ExportPublicKeyFactory as V3ExportPublicKeyFactory,
  ExportSecretKeyFactory as V3ExportSecretKeyFactory,
  GenerateKeyPairFactory as V3GenerateKeyPairFactory,
  PublicKeyIDFactory as V3PublicKeyIDFactory,
  type PublicKey as V3PublicKey,
  SecretKeyIDFactory as V3SecretKeyIDFactory,
} from 'paseto/v3/public'
import {
  GenerateKeyPairFactory as V4GenerateKeyPairFactory,
  ImportPublicKeyFactory as V4ImportPublicKeyFactory,
  PublicKeyFromCryptoKey as V4PublicKeyFromCryptoKey,
  PublicKeyToCryptoKey as V4PublicKeyToCryptoKey,
  SecretKeyFromCryptoKey as V4SecretKeyFromCryptoKey,
  SecretKeyToCryptoKey as V4SecretKeyToCryptoKey,
  SignFactory as V4SignFactory,
  type PublicKey as V4PublicKey,
  type SecretKey as V4SecretKey,
  VerifyFactory as V4VerifyFactory,
} from 'paseto/v4/public'

type Equals<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never

const _invalidTokenCode: Equals<PASETO.InvalidTokenError['code'], 'ERR_PASETO_INVALID_TOKEN'> = true
const _invalidPaserkCode: Equals<PASETO.InvalidPASERKError['code'], 'ERR_PASERK_INVALID'> = true
const _invalidKeyCode: Equals<PASETO.InvalidKeyError['code'], 'ERR_PASETO_INVALID_KEY'> = true
const _claimValidationCode: Equals<
  PASETO.ClaimValidationError['code'],
  'ERR_PASETO_CLAIM_VALIDATION'
> = true
const _unsupportedAlgorithmCode: Equals<
  PASETO.UnsupportedAlgorithmError['code'],
  'ERR_PASETO_UNSUPPORTED_ALGORITHM'
> = true

function exhaustiveErrorCode(code: PASETO.PasetoErrorCode): void {
  switch (code) {
    case 'ERR_PASETO_INVALID_TOKEN':
    case 'ERR_PASERK_INVALID':
    case 'ERR_PASETO_INVALID_KEY':
    case 'ERR_PASETO_CLAIM_VALIDATION':
    case 'ERR_PASETO_UNSUPPORTED_ALGORITHM':
      return
    default: {
      const _exhaustive: never = code
      return _exhaustive
    }
  }
}

exhaustiveErrorCode

const _localKeyType: Equals<V3LocalKey['type'], 'secret'> = true
const _localKeyAlgorithm: Equals<V3LocalKey['algorithm']['name'], 'PASETO v3.local'> = true
const _wrappingKeyType: Equals<V3WrappingKey['type'], 'secret'> = true
const _wrappingKeyAlgorithm: Equals<V3WrappingKey['algorithm']['name'], 'PASERK k3.wrap'> = true
const _sealingPublicKeyType: Equals<V3SealingPublicKey['type'], 'public'> = true
const _sealingPublicKeyExtractable: Equals<V3SealingPublicKey['extractable'], true> = true
const _sealingSecretKeyType: Equals<V3SealingSecretKey['type'], 'secret'> = true
const _publicKeyType: Equals<V4PublicKey['type'], 'public'> = true
const _publicKeyExtractable: Equals<V4PublicKey['extractable'], boolean> = true
const _secretKeyType: Equals<V4SecretKey['type'], 'secret'> = true
const _cryptoKeyIsHostCryptoKey: Equals<PASETO.CryptoKey, CryptoKey> = true

declare const nativeCryptoKey: CryptoKey

async function cryptoKeyAdaptersPreserveTypes() {
  const localKey = V3LocalKeyFromCryptoKey(nativeCryptoKey)
  const _localKey: Equals<typeof localKey, V3LocalKey> = true
  const localCryptoKey = V3LocalKeyToCryptoKey(localKey)
  const _localCryptoKey: Equals<typeof localCryptoKey, PASETO.CryptoKey> = true
  const _localHostCryptoKey: CryptoKey = localCryptoKey

  const secretKey = await V4SecretKeyFromCryptoKey(nativeCryptoKey)
  const _secretKey: Equals<typeof secretKey, V4SecretKey> = true
  const secretCryptoKey = V4SecretKeyToCryptoKey(secretKey)
  const _secretCryptoKey: Equals<typeof secretCryptoKey, PASETO.CryptoKey> = true
  const _secretHostCryptoKey: CryptoKey = secretCryptoKey

  const publicKey = await V4PublicKeyFromCryptoKey(nativeCryptoKey)
  const _publicKey: Equals<typeof publicKey, V4PublicKey> = true
  const publicCryptoKey = V4PublicKeyToCryptoKey(publicKey)
  const _publicCryptoKey: Equals<typeof publicCryptoKey, PASETO.CryptoKey> = true
  const _publicHostCryptoKey: CryptoKey = publicCryptoKey

  // @ts-expect-error v4 local keys are not accepted by the v3.local adapter.
  V3LocalKeyToCryptoKey({} as V4LocalKey)
  // @ts-expect-error v2 secret keys are not accepted by the v4.public adapter.
  V4SecretKeyToCryptoKey({} as V2SecretKey)
  // @ts-expect-error v3 public keys are not accepted by the v4.public adapter.
  V4PublicKeyToCryptoKey({} as V3PublicKey)
}

interface ApplicationClaims {
  sub: string
  role: 'admin' | 'user'
  permissions: readonly string[]
  preferences: { readonly compact: boolean }
}

type ApplicationTokenResult = PASETO.TokenResult<ApplicationClaims>
const _applicationClaims: Equals<ApplicationTokenResult['claims'], ApplicationClaims> = true
const _readonlyJsonValue: PASETO.JsonValue = {
  permissions: ['read', 'write'],
  nested: [{ enabled: true }],
} as const
const _registeredClaims: PASETO.Claims = {
  aud: 'urn:example',
  exp: '2030-01-01T00:00:00Z',
  iat: '2029-01-01T00:00:00Z',
}
// @ts-expect-error registered time claims are RFC 3339 strings, not numeric dates.
const _numericRegisteredClaim: PASETO.Claims = { exp: 1_893_456_000 }

declare const applicationClaims: ApplicationClaims
declare const numericExpirationClaims: { exp: number; role: string }
declare const nonJsonClaims: { sub: string; callback: () => void }

type ExplicitKeyPair = PASETO.KeyPair<V4PublicKey, V4SecretKey>
const _explicitPublicKey: Equals<ExplicitKeyPair['publicKey'], V4PublicKey> = true
const _explicitSecretKey: Equals<ExplicitKeyPair['secretKey'], V4SecretKey> = true
// @ts-expect-error asymmetric key-pair representations require both key types.
type IncompleteKeyPair = PASETO.KeyPair<V4PublicKey>

type CallableCapabilityFactory = PASETO.CapabilityFactory<'local', 3, 'Custom', () => Promise<void>>
declare const callableCapabilityFactory: CallableCapabilityFactory
callableCapabilityFactory
// @ts-expect-error a capability's run type must be callable.
type NonCallableCapabilityFactory = PASETO.CapabilityFactory<'local', 3, 'Custom', object>

const localReader = new PASETO.LocalProtocol(V3DecryptFactory, V3ImportKeyFactory)

async function selectedLocalReaderCapabilities() {
  const _version: Equals<typeof localReader.version, 3> = true
  const _purpose: Equals<typeof localReader.purpose, 'local'> = true
  const key = await localReader.ImportKey('k3.local.AA' as PASETO.LocalPASERK<3>)
  const _key: Equals<typeof key, V3LocalKey> = true
  const result = await localReader.Decrypt(key, 'v3.local.AA')
  const _claims: Equals<typeof result.claims, PASETO.Claims> = true
  // @ts-expect-error authenticated claims are not narrowed to an application-specific type.
  const _subject: string = result.claims.sub
  const _footer: Uint8Array = result.footer
  const _inspected: Uint8Array = PASETO.InspectFooter('v3.local.AA')

  // @ts-expect-error Decrypt does not accept a caller-selected claims type.
  await localReader.Decrypt<{ sub: string }>(key, 'v3.local.AA')
  const directResult = await V3DecryptFactory().run(key, 'v3.local.AA')
  const _directClaims: Equals<typeof directResult.claims, PASETO.Claims> = true
  await localReader.Decrypt(key, 'v3.local.AA', { implicitAssertion: new Uint8Array() })
  await V3DecryptFactory().run(key, 'v3.local.AA', { implicitAssertion: new Uint8Array() })
  // @ts-expect-error the direct Decrypt capability does not accept a claims type either.
  await V3DecryptFactory().run<{ sub: string }>(key, 'v3.local.AA')

  // @ts-expect-error Encrypt was not selected.
  localReader.Encrypt
  // @ts-expect-error GenerateKey was not selected.
  localReader.GenerateKey
  // @ts-expect-error ExportKey was not selected.
  localReader.ExportKey
  // @ts-expect-error KeyID was not selected.
  localReader.KeyID
  // @ts-expect-error composed protocols do not expose a PASERK namespace.
  localReader.PASERK
  // @ts-expect-error footer inspection is a protocol-independent root function.
  localReader.InspectFooter

  const v4Key = await localWriter.ImportKey('k4.local.AA' as PASETO.LocalPASERK<4>)
  // @ts-expect-error keys remain bound to their literal protocol version.
  await localReader.Decrypt(v4Key, 'v3.local.AA')
}

const localWriter = new PASETO.LocalProtocol(
  V4GenerateKeyFactory,
  V4ImportKeyFactory,
  V4ExportKeyFactory,
)

async function selectedLocalWriterCapabilities() {
  const _version: Equals<typeof localWriter.version, 4> = true
  const key = await localWriter.GenerateKey({ extractable: true })
  const _key: Equals<typeof key, V4LocalKey> = true
  const serialized = await localWriter.ExportKey(key)
  const _serialized: Equals<typeof serialized, PASETO.LocalPASERK<4>> = true
  const imported = await localWriter.ImportKey(serialized)
  const _imported: Equals<typeof imported, V4LocalKey> = true
  PASETO.InspectFooter('v4.local.AA')

  // @ts-expect-error Decrypt was not selected.
  localWriter.Decrypt
  // @ts-expect-error wrapping operations were not selected.
  localWriter.GenerateWrappingKey
}

const localPaserk = new PASETO.LocalProtocol(
  V3GenerateKeyFactory,
  V3ExportKeyFactory,
  V3KeyIDFactory,
  V3GenerateWrappingKeyFactory,
  V3ImportWrappingKeyFactory,
  V3ExportWrappingKeyFactory,
  V3WrapKeyFactory,
)

const sealingKeys = new PASETO.LocalProtocol(
  V3GenerateSealingKeyPairFactory,
  V3ImportSealingSecretKeyFactory,
  V3ExportSealingSecretKeyFactory,
)

const localPasswordUnwrap = new PASETO.LocalProtocol(V3UnwrapKeyWithPasswordFactory)
declare const passwordWrappedLocal: PASETO.PasswordWrappedLocalPASERK<3>
declare const password: Uint8Array

async function passwordUnwrapOptionsAreMerged() {
  const key = await localPasswordUnwrap.UnwrapKeyWithPassword(passwordWrappedLocal, password, {
    maxIterations: 10_000,
    extractable: true,
  })
  const _key: Equals<typeof key, V3LocalKey> = true
  const _options: PASETO.PasswordUnwrapOptions<3> = { maxIterations: 10_000, extractable: true }
  await V3UnwrapKeyWithPasswordFactory().run(passwordWrappedLocal, password, {
    maxIterations: 10_000,
  })

  // @ts-expect-error v1/v3 password unwrapping accepts PBKDF2 limits, not Argon2id limits.
  await localPasswordUnwrap.UnwrapKeyWithPassword(passwordWrappedLocal, password, { maxMemory: 1 })
  // @ts-expect-error the direct capability keeps the v3 PBKDF2 option family.
  await V3UnwrapKeyWithPasswordFactory().run(passwordWrappedLocal, password, { maxMemory: 1 })

  const _argonOptions: PASETO.PasswordUnwrapOptions<4> = {
    maxMemory: 1024,
    maxPasses: 2,
    maxParallelism: 1,
    extractable: true,
  }
  // @ts-expect-error v2/v4 password unwrapping accepts Argon2id limits, not PBKDF2 limits.
  const _invalidArgonOptions: PASETO.PasswordUnwrapOptions<4> = { maxIterations: 10_000 }

  await localPasswordUnwrap.UnwrapKeyWithPassword(
    passwordWrappedLocal,
    password,
    { maxIterations: 10_000 },
    // @ts-expect-error password unwrap accepts one options object.
    { extractable: true },
  )
}

{
  const _pbkdf2WrapOptions: PASETO.PasswordWrapOptions<3> = { iterations: 100_000 }
  const _argon2idWrapOptions: PASETO.PasswordWrapOptions<4> = {
    memory: 64 * 1024 * 1024,
    passes: 2,
    parallelism: 1,
  }

  const pbkdf2WrapOptions = { iterations: 100_000 }
  // @ts-expect-error variables cannot add PBKDF2 parameters to v2/v4 wrapping options.
  const _invalidArgon2idWrapVariable: PASETO.PasswordWrapOptions<4> = pbkdf2WrapOptions
  const argon2idWrapOptions = { memory: 64 * 1024 * 1024, passes: 2, parallelism: 1 }
  // @ts-expect-error spreads cannot add Argon2id parameters to v1/v3 wrapping options.
  const _invalidPbkdf2WrapSpread: PASETO.PasswordWrapOptions<3> = { ...argon2idWrapOptions }
}

async function selectedLocalPaserkCapabilities() {
  const key = await localPaserk.GenerateKey({ extractable: true })
  const wrappingKey = await localPaserk.GenerateWrappingKey({ extractable: true })
  const _wrappingKey: Equals<typeof wrappingKey, V3WrappingKey> = true
  const wrappingKeyMaterial = await localPaserk.ExportWrappingKey(wrappingKey)
  await localPaserk.ImportWrappingKey(wrappingKeyMaterial, { extractable: true })
  const serialized = await localPaserk.ExportKey(key)
  const identifier = await localPaserk.KeyID(serialized)
  const _identifier: Equals<typeof identifier, PASETO.LocalIdPASERK<3>> = true
  const wrapped = await localPaserk.WrapKey(key, wrappingKey)
  await localPaserk.KeyID(wrapped)
  const _wrapped: Equals<typeof wrapped, PASETO.WrappedLocalPASERK<3, 'pie'>> = true

  // @ts-expect-error local identifiers are derived from compatible serialized PASERKs, not keys.
  await localPaserk.KeyID(key)
  // @ts-expect-error secret PASERKs are not compatible with local identifiers.
  await localPaserk.KeyID('k3.secret.AA')

  // @ts-expect-error the inverse operation was not selected.
  localPaserk.UnwrapKey
}

async function auxiliarySecretExtractabilityOptions() {
  const { secretKey } = await sealingKeys.GenerateSealingKeyPair({ extractable: true })
  const material = await sealingKeys.ExportSealingSecretKey(secretKey)
  await sealingKeys.ImportSealingSecretKey(material, { extractable: true })
}

declare const extensionKey: PASETO.Key

const customLocalWrap = PASETO.LocalWrapKey<4, PASETO.Key, PASETO.Key, 'aws-kms'>({
  version: 4,
  run: async () => 'k4.local-wrap.aws-kms.payload' as const,
})
const customLocalUnwrap = PASETO.LocalUnwrapKey<4, PASETO.Key, PASETO.Key, 'aws-kms'>({
  version: 4,
  run: async (paserk) => {
    const _paserk: PASETO.WrappedLocalPASERK<4, 'aws-kms'> = paserk
    return extensionKey
  },
})

async function customLocalWrapPrefixIsPreserved() {
  const wrapped = await customLocalWrap().run(extensionKey, extensionKey)
  const _wrapped: Equals<typeof wrapped, PASETO.WrappedLocalPASERK<4, 'aws-kms'>> = true
  await customLocalUnwrap().run(wrapped, extensionKey)
  // @ts-expect-error custom wrapping capabilities reject a different wrapping protocol prefix.
  await customLocalUnwrap().run('k4.local-wrap.pie.payload', extensionKey)
}

const customSecretWrap = PASETO.PublicWrapSecretKey<4, PASETO.Key, PASETO.Key, 'aws-kms'>({
  version: 4,
  run: async () => 'k4.secret-wrap.aws-kms.payload' as const,
})
const customSecretUnwrap = PASETO.PublicUnwrapSecretKey<4, PASETO.Key, PASETO.Key, 'aws-kms'>({
  version: 4,
  run: async (paserk) => {
    const _paserk: PASETO.WrappedSecretPASERK<4, 'aws-kms'> = paserk
    return extensionKey
  },
})

async function customSecretWrapPrefixIsPreserved() {
  const wrapped = await customSecretWrap().run(extensionKey, extensionKey)
  const _wrapped: Equals<typeof wrapped, PASETO.WrappedSecretPASERK<4, 'aws-kms'>> = true
  await customSecretUnwrap().run(wrapped, extensionKey)
  // @ts-expect-error custom wrapping capabilities reject a different wrapping protocol prefix.
  await customSecretUnwrap().run('k4.secret-wrap.pie.payload', extensionKey)
}

const publicVerifier = new PASETO.PublicProtocol(V4VerifyFactory, V4ImportPublicKeyFactory)

async function selectedPublicVerifierCapabilities() {
  const _version: Equals<typeof publicVerifier.version, 4> = true
  const _purpose: Equals<typeof publicVerifier.purpose, 'public'> = true
  const key = await publicVerifier.ImportPublicKey('k4.public.AA' as PASETO.PublicPASERK<4>)
  const _key: Equals<typeof key, V4PublicKey> = true
  const result = await publicVerifier.Verify(key, 'v4.public.AA')
  const _claims: Equals<typeof result.claims, PASETO.Claims> = true
  // @ts-expect-error authenticated claims are not narrowed to an application-specific type.
  const _audience: string = result.claims.aud

  // @ts-expect-error Verify does not accept a caller-selected claims type.
  await publicVerifier.Verify<{ aud: string }>(key, 'v4.public.AA')
  const directResult = await V4VerifyFactory().run(key, 'v4.public.AA')
  const _directClaims: Equals<typeof directResult.claims, PASETO.Claims> = true
  // @ts-expect-error the direct Verify capability does not accept a claims type either.
  await V4VerifyFactory().run<{ aud: string }>(key, 'v4.public.AA')

  // @ts-expect-error Sign was not selected.
  publicVerifier.Sign
  // @ts-expect-error key-pair generation was not selected.
  publicVerifier.GenerateKeyPair
  // @ts-expect-error secret-key import was not selected.
  publicVerifier.ImportSecretKey
  // @ts-expect-error public-key export was not selected.
  publicVerifier.ExportPublicKey
}

const publicSigner = new PASETO.PublicProtocol(V4GenerateKeyPairFactory, V4SignFactory)

async function selectedPublicSignerCapabilities() {
  const pair = await publicSigner.GenerateKeyPair()
  const _publicKey: Equals<typeof pair.publicKey, V4PublicKey> = true
  const _secretKey: Equals<typeof pair.secretKey, V4SecretKey> = true
  const token = await publicSigner.Sign(
    pair.secretKey,
    { aud: 'example' },
    { implicitAssertion: new Uint8Array() },
  )
  await V4SignFactory().run(pair.secretKey, {}, { implicitAssertion: new Uint8Array() })
  await publicSigner.Sign(pair.secretKey, applicationClaims)
  await V4SignFactory().run(pair.secretKey, applicationClaims)
  await publicSigner.Sign(pair.secretKey, { sub: 'alice', permissions: ['read', 'write'] as const })
  // @ts-expect-error registered time claims are RFC 3339 strings, not numeric dates.
  await publicSigner.Sign(pair.secretKey, { exp: 1_893_456_000 })
  // @ts-expect-error widening an invalid registered claim does not bypass claims validation.
  await publicSigner.Sign(pair.secretKey, numericExpirationClaims)
  // @ts-expect-error functions are not JSON claim values.
  await publicSigner.Sign(pair.secretKey, nonJsonClaims)
  const _token: string = token

  // @ts-expect-error public verification keys cannot sign tokens.
  await publicSigner.Sign(pair.publicKey, {})
  // @ts-expect-error Verify was not selected.
  publicSigner.Verify
  // @ts-expect-error GetPublicKey was not selected.
  publicSigner.GetPublicKey
  // @ts-expect-error composed protocols do not expose a PASERK namespace.
  publicSigner.PASERK
}

const publicPaserk = new PASETO.PublicProtocol(
  V3GenerateKeyPairFactory,
  V3ExportPublicKeyFactory,
  V3ExportSecretKeyFactory,
  V3PublicKeyIDFactory,
  V3SecretKeyIDFactory,
)

async function selectedPublicPaserkCapabilities() {
  const pair = await publicPaserk.GenerateKeyPair({ extractable: true })
  const publicSerialized = await publicPaserk.ExportPublicKey(pair.publicKey)
  const secretSerialized = await publicPaserk.ExportSecretKey(pair.secretKey)
  const publicIdentifier = await publicPaserk.PublicKeyID(publicSerialized)
  const secretIdentifier = await publicPaserk.SecretKeyID(secretSerialized)
  const _publicSerialized: Equals<typeof publicSerialized, PASETO.PublicPASERK<3>> = true
  const _secretSerialized: Equals<typeof secretSerialized, PASETO.SecretPASERK<3>> = true
  const _publicIdentifier: Equals<typeof publicIdentifier, PASETO.PublicIdPASERK<3>> = true
  const _secretIdentifier: Equals<typeof secretIdentifier, PASETO.SecretIdPASERK<3>> = true

  // @ts-expect-error public identifiers are derived from public PASERKs, not keys.
  await publicPaserk.PublicKeyID(pair.publicKey)
  // @ts-expect-error local PASERKs are not compatible with secret identifiers.
  await publicPaserk.SecretKeyID('k3.local.AA')

  // @ts-expect-error symmetric protection was not selected.
  publicPaserk.WrapSecretKey
}

interface CustomLocalKey extends PASETO.Key {
  readonly handle: symbol
}

declare const customLocalKey: CustomLocalKey
declare const v2SecretKey: V2SecretKey

const CustomDecryptFactory = PASETO.LocalDecrypt<2, CustomLocalKey>({
  version: 2,
  async run(key, payload) {
    void key.handle
    return payload
  },
})
const CustomEncryptFactory = PASETO.LocalEncrypt<2, CustomLocalKey>({
  version: 2,
  async run(key, plaintext) {
    void key.handle
    return plaintext
  },
})
const customLocal = new PASETO.LocalProtocol(CustomDecryptFactory, CustomEncryptFactory)
const _customVersion: Equals<typeof customLocal.version, 2> = true
const _customKey: Equals<Parameters<typeof customLocal.Decrypt>[0], CustomLocalKey> = true

async function customLocalClaimsTyping() {
  await customLocal.Encrypt(customLocalKey, applicationClaims)
  await CustomEncryptFactory().run(customLocalKey, applicationClaims)
  // @ts-expect-error registered time claims are RFC 3339 strings, not numeric dates.
  await customLocal.Encrypt(customLocalKey, numericExpirationClaims)
}

type _V1EncryptArity = Equals<
  Parameters<PASETO.LocalEncryptImplementation<1, CustomLocalKey>['run']>['length'],
  3
>
const _v1EncryptArity: _V1EncryptArity = true
type _V2DecryptArity = Equals<
  Parameters<PASETO.LocalDecryptImplementation<2, CustomLocalKey>['run']>['length'],
  3
>
const _v2DecryptArity: _V2DecryptArity = true
type _V1SignArity = Equals<
  Parameters<PASETO.PublicSignImplementation<1, CustomLocalKey>['run']>['length'],
  3
>
const _v1SignArity: _V1SignArity = true
type _V2VerifyArity = Equals<
  Parameters<PASETO.PublicVerifyImplementation<2, CustomLocalKey>['run']>['length'],
  4
>
const _v2VerifyArity: _V2VerifyArity = true
type _V3EncryptArity = Equals<
  Parameters<PASETO.LocalEncryptImplementation<3, CustomLocalKey>['run']>['length'],
  4
>
const _v3EncryptArity: _V3EncryptArity = true
type _V4VerifyArity = Equals<
  Parameters<PASETO.PublicVerifyImplementation<4, CustomLocalKey>['run']>['length'],
  5
>
const _v4VerifyArity: _V4VerifyArity = true

async function implicitAssertionsAreVersionBound() {
  await customLocal.Decrypt(customLocalKey, 'v2.local.AA', {
    // @ts-expect-error v1/v2 token consumption does not support implicit assertions.
    implicitAssertion: new Uint8Array(),
  })
  await CustomDecryptFactory().run(customLocalKey, 'v2.local.AA', {
    // @ts-expect-error the direct v2 capability also excludes implicit assertions.
    implicitAssertion: new Uint8Array(),
  })
  // @ts-expect-error v1/v2 token production does not support implicit assertions.
  await V2SignFactory().run(v2SecretKey, {}, { implicitAssertion: new Uint8Array() })

  const v2Signer = new PASETO.PublicProtocol(V2SignFactory)
  // @ts-expect-error composed v2 signing methods retain the version-specific options.
  await v2Signer.Sign(v2SecretKey, {}, { implicitAssertion: new Uint8Array() })

  const _earlyProduce: PASETO.ProduceOptions<2> = { footer: new Uint8Array() }
  const _lateConsume: PASETO.ConsumeOptions<4> = { implicitAssertion: new Uint8Array() }
  // @ts-expect-error v1/v2 option aliases exclude implicit assertions.
  const _earlyConsume: PASETO.ConsumeOptions<1> = { implicitAssertion: new Uint8Array() }
  // @ts-expect-error explicitly undefined implicit assertions are still unavailable in v1/v2.
  const _undefinedEarlyProduce: PASETO.ProduceOptions<2> = { implicitAssertion: undefined }
  // @ts-expect-error explicitly undefined implicit assertions are still unavailable in v1/v2.
  const _undefinedEarlyConsume: PASETO.ConsumeOptions<1> = { implicitAssertion: undefined }

  const implicitAssertionOptions = { implicitAssertion: new Uint8Array() }
  // @ts-expect-error variables cannot bypass the v1/v2 implicit-assertion exclusion.
  const _earlyProduceVariable: PASETO.ProduceOptions<2> = implicitAssertionOptions
  // @ts-expect-error spreads cannot bypass the v1/v2 implicit-assertion exclusion.
  const _earlyConsumeSpread: PASETO.ConsumeOptions<1> = { ...implicitAssertionOptions }
  const implicitAssertionWithFooter = { footer: new Uint8Array(), implicitAssertion: undefined }
  // @ts-expect-error valid common fields do not let variables add unavailable options.
  await customLocal.Decrypt(customLocalKey, 'v2.local.AA', implicitAssertionWithFooter)
  const widenedEarlyOptions = { footer: new Uint8Array(), implicitAssertion: new Uint8Array() }
  // @ts-expect-error widening does not let v3/v4-only options enter a v1/v2 option alias.
  const _widenedEarlyOptions: PASETO.ProduceOptions<2> = widenedEarlyOptions

  // @ts-expect-error a mixed-version option type does not prove implicit assertions are available.
  const _mixedProduce: PASETO.ProduceOptions<1 | 3> = { implicitAssertion: new Uint8Array() }
  const _genericConsume: PASETO.ConsumeOptions<PASETO.Version> = {
    // @ts-expect-error the unconstrained version type exposes only common consumption options.
    implicitAssertion: new Uint8Array(),
  }
}

{
  const _expiring: PASETO.ProduceOptions<4> = { expiresIn: 60, nonExpiring: false }
  const _nonExpiring: PASETO.ProduceOptions<4> = { nonExpiring: true }
  const _conflictingExpiration: PASETO.ProduceOptions<4> = { expiresIn: 60, nonExpiring: true }
}

async function exportedOptionAliasesRemainForwardable(options: PASETO.ProduceOptions<2>) {
  await new PASETO.PublicProtocol(V2SignFactory).Sign(v2SecretKey, {}, options)
}

const CustomV4PasswordUnwrapFactory = PASETO.LocalUnwrapKeyWithPassword<4, CustomLocalKey>({
  version: 4,
  async run(_paserk, _password, limits) {
    const _memory: number | undefined = limits.maxMemory
    // @ts-expect-error a v4 low-level implementation receives only Argon2id limits.
    limits.maxIterations
    return customLocalKey
  },
})
const customV4PasswordUnwrap = new PASETO.LocalProtocol(CustomV4PasswordUnwrapFactory)
declare const passwordWrappedV4Local: PASETO.PasswordWrappedLocalPASERK<4>

async function argonPasswordUnwrapOptionsArePreserved() {
  await customV4PasswordUnwrap.UnwrapKeyWithPassword(passwordWrappedV4Local, password, {
    maxMemory: 1024,
    extractable: true,
  })
  await CustomV4PasswordUnwrapFactory().run(passwordWrappedV4Local, password, { maxPasses: 2 })
  await customV4PasswordUnwrap.UnwrapKeyWithPassword(passwordWrappedV4Local, password, {
    // @ts-expect-error composed v4 password unwrapping excludes PBKDF2 limits.
    maxIterations: 10_000,
  })

  const pbkdf2Limits = { extractable: true, maxIterations: 10_000 }
  await customV4PasswordUnwrap.UnwrapKeyWithPassword(
    passwordWrappedV4Local,
    password,
    // @ts-expect-error variables cannot add PBKDF2 limits to v2/v4 options.
    pbkdf2Limits,
  )
  const argon2idLimits = { extractable: true, maxMemory: 1024 }
  // @ts-expect-error variables cannot add Argon2id limits to v1/v3 options.
  await localPasswordUnwrap.UnwrapKeyWithPassword(passwordWrappedLocal, password, argon2idLimits)

  const widenedPbkdf2Options = { iterations: 100_000, memory: 1024 }
  // @ts-expect-error widening does not mix password KDF parameter families.
  const _widenedPbkdf2Options: PASETO.PasswordWrapOptions<3> = widenedPbkdf2Options

  // @ts-expect-error unavailable PBKDF2 fields remain unavailable when explicitly undefined.
  const _undefinedArgonUnwrap: PASETO.PasswordUnwrapOptions<4> = { maxIterations: undefined }
  // @ts-expect-error unavailable Argon2id fields remain unavailable when explicitly undefined.
  const _undefinedPbkdf2Unwrap: PASETO.PasswordUnwrapOptions<3> = { maxMemory: undefined }
  // @ts-expect-error unavailable PBKDF2 fields remain unavailable when explicitly undefined.
  const _undefinedArgonWrap: PASETO.PasswordWrapOptions<2> = { iterations: undefined }
  // @ts-expect-error unavailable Argon2id fields remain unavailable when explicitly undefined.
  const _undefinedPbkdf2Wrap: PASETO.PasswordWrapOptions<1> = { memory: undefined }

  // @ts-expect-error a mixed KDF-family version does not expose PBKDF2 parameters.
  const _mixedPasswordWrap: PASETO.PasswordWrapOptions<1 | 2> = { iterations: 100_000 }
  // @ts-expect-error a mixed KDF-family version does not expose Argon2id limits.
  const _mixedPasswordUnwrap: PASETO.PasswordUnwrapOptions<3 | 4> = { maxMemory: 1024 }
}

const customLocalFactories = [
  CustomDecryptFactory,
] as const satisfies PASETO.LocalProtocolFactories<2>
const versionAnnotatedCustomLocal = new PASETO.LocalProtocol(...customLocalFactories)
const _annotatedCustomVersion: Equals<typeof versionAnnotatedCustomLocal.version, 2> = true
const _annotatedCustomKey: Equals<
  Parameters<typeof versionAnnotatedCustomLocal.Decrypt>[0],
  CustomLocalKey
> = true

const v4PublicFactories = [V4VerifyFactory] as const satisfies PASETO.PublicProtocolFactories<4>
const versionAnnotatedPublic = new PASETO.PublicProtocol(...v4PublicFactories)
const _annotatedPublicVersion: Equals<typeof versionAnnotatedPublic.version, 4> = true
versionAnnotatedPublic.Verify

function composeOneGenericLocal<V extends PASETO.Version>(
  factory: PASETO.LocalCapabilityFactory<V, 'Decrypt'>,
) {
  return new PASETO.LocalProtocol(factory)
}

declare const genericVersionDecryptFactory: PASETO.LocalCapabilityFactory<PASETO.Version, 'Decrypt'>
const genericSingleton = composeOneGenericLocal(genericVersionDecryptFactory)
genericSingleton.Decrypt
const _genericSingletonVersion: Equals<typeof genericSingleton.version, PASETO.Version> = true

declare const annotatedDecryptFactory: PASETO.LocalCapabilityFactory<3, 'Decrypt'>
declare const annotatedVerifyFactory: PASETO.PublicCapabilityFactory<4, 'Verify'>
const annotatedEncryptFactory: PASETO.LocalCapabilityFactory<2, 'Encrypt'> = CustomEncryptFactory
const annotatedSignFactory: PASETO.PublicCapabilityFactory<2, 'Sign'> = V2SignFactory

async function annotatedFactoriesRetainOperationSignatures(key: PASETO.Key) {
  const local = new PASETO.LocalProtocol(annotatedDecryptFactory)
  const decrypted = await local.Decrypt(key, 'v3.local.AA', { implicitAssertion: new Uint8Array() })
  const _localResult: Equals<typeof decrypted, PASETO.TokenResult> = true

  const publicProtocol = new PASETO.PublicProtocol(annotatedVerifyFactory)
  const verified = await publicProtocol.Verify(key, 'v4.public.AA', {
    implicitAssertion: new Uint8Array(),
  })
  const _publicResult: Equals<typeof verified, PASETO.TokenResult> = true

  const localProducer = new PASETO.LocalProtocol(annotatedEncryptFactory)
  const publicProducer = new PASETO.PublicProtocol(annotatedSignFactory)
  await localProducer.Encrypt(key, applicationClaims)
  await publicProducer.Sign(key, applicationClaims)
  // @ts-expect-error annotated producer factories retain registered-claim constraints.
  await localProducer.Encrypt(key, numericExpirationClaims)
  // @ts-expect-error annotated producer factories retain JSON-value constraints.
  await publicProducer.Sign(key, nonJsonClaims)

  const lateVersionOptions = { implicitAssertion: new Uint8Array() }
  // @ts-expect-error annotated v2 producer factories retain their version-specific options.
  await localProducer.Encrypt(key, {}, lateVersionOptions)
  // @ts-expect-error annotated v2 producer factories retain their version-specific options.
  await publicProducer.Sign(key, {}, lateVersionOptions)
}

annotatedFactoriesRetainOperationSignatures

declare const everyV3LocalFactory: readonly [
  PASETO.LocalCapabilityFactory<3, 'GenerateKey'>,
  PASETO.LocalCapabilityFactory<3, 'Encrypt'>,
  PASETO.LocalCapabilityFactory<3, 'Decrypt'>,
  PASETO.LocalCapabilityFactory<3, 'ImportKey'>,
  PASETO.LocalCapabilityFactory<3, 'ExportKey'>,
  PASETO.LocalCapabilityFactory<3, 'KeyID'>,
  PASETO.LocalCapabilityFactory<3, 'GenerateWrappingKey'>,
  PASETO.LocalCapabilityFactory<3, 'ImportWrappingKey'>,
  PASETO.LocalCapabilityFactory<3, 'ExportWrappingKey'>,
  PASETO.LocalCapabilityFactory<3, 'WrapKey'>,
  PASETO.LocalCapabilityFactory<3, 'UnwrapKey'>,
  PASETO.LocalCapabilityFactory<3, 'WrapKeyWithPassword'>,
  PASETO.LocalCapabilityFactory<3, 'UnwrapKeyWithPassword'>,
  PASETO.LocalCapabilityFactory<3, 'GenerateSealingKeyPair'>,
  PASETO.LocalCapabilityFactory<3, 'ImportSealingPublicKey'>,
  PASETO.LocalCapabilityFactory<3, 'ImportSealingSecretKey'>,
  PASETO.LocalCapabilityFactory<3, 'ExportSealingPublicKey'>,
  PASETO.LocalCapabilityFactory<3, 'ExportSealingSecretKey'>,
  PASETO.LocalCapabilityFactory<3, 'SealKey'>,
  PASETO.LocalCapabilityFactory<3, 'UnsealKey'>,
]
const everyV3Local = new PASETO.LocalProtocol(...everyV3LocalFactory)
const _everyLocalOperation: Equals<
  Exclude<PASETO.LocalOperation, keyof typeof everyV3Local>,
  never
> = true

declare const everyV4PublicFactory: readonly [
  PASETO.PublicCapabilityFactory<4, 'GenerateKeyPair'>,
  PASETO.PublicCapabilityFactory<4, 'Sign'>,
  PASETO.PublicCapabilityFactory<4, 'Verify'>,
  PASETO.PublicCapabilityFactory<4, 'ImportPublicKey'>,
  PASETO.PublicCapabilityFactory<4, 'ExportPublicKey'>,
  PASETO.PublicCapabilityFactory<4, 'ImportSecretKey'>,
  PASETO.PublicCapabilityFactory<4, 'ExportSecretKey'>,
  PASETO.PublicCapabilityFactory<4, 'GetPublicKey'>,
  PASETO.PublicCapabilityFactory<4, 'PublicKeyID'>,
  PASETO.PublicCapabilityFactory<4, 'SecretKeyID'>,
  PASETO.PublicCapabilityFactory<4, 'GenerateWrappingKey'>,
  PASETO.PublicCapabilityFactory<4, 'ImportWrappingKey'>,
  PASETO.PublicCapabilityFactory<4, 'ExportWrappingKey'>,
  PASETO.PublicCapabilityFactory<4, 'WrapSecretKey'>,
  PASETO.PublicCapabilityFactory<4, 'UnwrapSecretKey'>,
  PASETO.PublicCapabilityFactory<4, 'WrapSecretKeyWithPassword'>,
  PASETO.PublicCapabilityFactory<4, 'UnwrapSecretKeyWithPassword'>,
]
const everyV4Public = new PASETO.PublicProtocol(...everyV4PublicFactory)
const _everyPublicOperation: Equals<
  Exclude<PASETO.PublicOperation, keyof typeof everyV4Public>,
  never
> = true

declare const opaqueV3LocalFactories: PASETO.LocalProtocolFactories<3>
const opaqueV3Local = new PASETO.LocalProtocol(...opaqueV3LocalFactories)
const _opaqueV3LocalVersion: Equals<typeof opaqueV3Local.version, 3> = true
const _opaqueV3LocalPurpose: Equals<typeof opaqueV3Local.purpose, 'local'> = true
// @ts-expect-error an opaque factory collection does not prove that Decrypt was selected.
opaqueV3Local.Decrypt
// @ts-expect-error an opaque factory collection does not prove that GenerateKey was selected.
opaqueV3Local.GenerateKey

declare const opaqueV4PublicFactories: PASETO.PublicProtocolFactories<4>
const opaqueV4Public = new PASETO.PublicProtocol(...opaqueV4PublicFactories)
const _opaqueV4PublicVersion: Equals<typeof opaqueV4Public.version, 4> = true
const _opaqueV4PublicPurpose: Equals<typeof opaqueV4Public.purpose, 'public'> = true
// @ts-expect-error an opaque factory collection does not prove that Verify was selected.
opaqueV4Public.Verify
// @ts-expect-error an opaque factory collection does not prove that Sign was selected.
opaqueV4Public.Sign

declare const uncertainLocalFactory:
  PASETO.LocalCapabilityFactory<3, 'Encrypt'> | PASETO.LocalCapabilityFactory<3, 'Decrypt'>
const uncertainLocal = new PASETO.LocalProtocol(uncertainLocalFactory)
// @ts-expect-error a union-valued factory does not prove that Encrypt was selected.
uncertainLocal.Encrypt
// @ts-expect-error a union-valued factory does not prove that Decrypt was selected.
uncertainLocal.Decrypt

declare const uncertainPublicFactory:
  PASETO.PublicCapabilityFactory<4, 'Sign'> | PASETO.PublicCapabilityFactory<4, 'Verify'>
const uncertainPublic = new PASETO.PublicProtocol(uncertainPublicFactory)
// @ts-expect-error a union-valued factory does not prove that Sign was selected.
uncertainPublic.Sign
// @ts-expect-error a union-valued factory does not prove that Verify was selected.
uncertainPublic.Verify

declare const uncertainLocalTuple:
  | readonly [PASETO.LocalCapabilityFactory<3, 'Encrypt'>]
  | readonly [PASETO.LocalCapabilityFactory<3, 'Decrypt'>]
const uncertainLocalTupleProtocol = new PASETO.LocalProtocol(...uncertainLocalTuple)
// @ts-expect-error a union of tuples does not prove that Encrypt was selected.
uncertainLocalTupleProtocol.Encrypt
// @ts-expect-error a union of tuples does not prove that Decrypt was selected.
uncertainLocalTupleProtocol.Decrypt

declare const openLocalTuple: readonly [
  PASETO.LocalCapabilityFactory<3, 'Encrypt'>,
  ...(PASETO.LocalCapabilityFactory<3, 'Encrypt'> | PASETO.LocalCapabilityFactory<3, 'Decrypt'>)[],
]
const openLocalTupleProtocol = new PASETO.LocalProtocol(...openLocalTuple)
openLocalTupleProtocol.Encrypt
// @ts-expect-error an optional rest element does not prove that Decrypt was selected.
openLocalTupleProtocol.Decrypt

declare const unversionedLocalFactories: PASETO.LocalProtocolFactories

{
  // @ts-expect-error at least one capability is required.
  new PASETO.LocalProtocol()
  // @ts-expect-error a public-purpose capability cannot be composed as local.
  new PASETO.LocalProtocol(V4VerifyFactory)
  // @ts-expect-error a local-purpose capability cannot be composed as public.
  new PASETO.PublicProtocol(V3DecryptFactory)
  // @ts-expect-error an operation can only be selected once.
  new PASETO.LocalProtocol(V3DecryptFactory, V3DecryptFactory)
  // @ts-expect-error all selected local capabilities must have one version.
  new PASETO.LocalProtocol(V3DecryptFactory, V4ImportKeyFactory)
  // @ts-expect-error all selected public capabilities must have one version.
  new PASETO.PublicProtocol(V4VerifyFactory, V3ExportPublicKeyFactory)
  // @ts-expect-error a broadly versioned tuple is not provably bound to one version.
  new PASETO.LocalProtocol(...unversionedLocalFactories)

  const forgedLocalFactory = () => ({
    purpose: 'local' as const,
    version: 3 as const,
    operation: 'Decrypt' as const,
    run: async () => ({ claims: {}, footer: new Uint8Array() }),
  })
  // Capability factories are structural across package copies; the constructor validates the
  // runtime marker before invoking one.
  new PASETO.LocalProtocol(forgedLocalFactory)

  // @ts-expect-error root no longer exports pre-bound version aggregates.
  PASETO.V4_PUBLIC
  // @ts-expect-error protocol metadata is readonly.
  localReader.version = 4
}

{
  const encoded = PASETO.PAE([new Uint8Array(), Uint8Array.of(1)])
  const _encoded: Uint8Array = encoded
}
