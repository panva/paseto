import {
  xchacha20 as nobleXChaCha20,
  xchacha20poly1305 as nobleXChaCha20Poly1305,
} from '@noble/ciphers/chacha.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { blake2b as nobleBlake2b } from '@noble/hashes/blake2.js'
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js'

import {
  InvalidKeyError,
  InvalidPASERKError,
  InvalidTokenError,
  KDF_ARGON2ID,
  LocalDecrypt,
  LocalEncrypt,
  LocalExportKey,
  LocalExportSealingPublicKey,
  LocalExportSealingSecretKey,
  LocalExportWrappingKey,
  LocalGenerateKey,
  LocalGenerateSealingKeyPair,
  LocalGenerateWrappingKey,
  LocalImportKey,
  LocalImportSealingPublicKey,
  LocalImportSealingSecretKey,
  LocalImportWrappingKey,
  LocalKeyID,
  LocalSealKey,
  LocalUnsealKey,
  LocalUnwrapKey,
  LocalUnwrapKeyWithPassword,
  LocalWrapKey,
  LocalWrapKeyWithPassword,
  PublicExportPublicKey,
  PublicExportSecretKey,
  PublicExportWrappingKey,
  PublicGenerateKeyPair,
  PublicGenerateWrappingKey,
  PublicGetPublicKey,
  PublicImportPublicKey,
  PublicImportSecretKey,
  PublicImportWrappingKey,
  PublicKeyID,
  SecretKeyID,
  PublicSign,
  PublicUnwrapSecretKey,
  PublicUnwrapSecretKeyWithPassword,
  PublicVerify,
  PublicWrapSecretKey,
  PublicWrapSecretKeyWithPassword,
  type Argon2id,
  type Argon2idFactory,
  type Argon2idParameters,
  type KeyOptions,
  type Key,
  type KeyPair,
  type LocalIdPASERK,
  type LocalPASERK,
  type PasswordWrapOptions,
  type PasswordWrappedLocalPASERK,
  type PasswordWrappedSecretPASERK,
  type PublicIdPASERK,
  type PublicPASERK,
  type SealedLocalPASERK,
  type SecretIdPASERK,
  type SecretPASERK,
  type WrappedLocalPASERK,
  type WrappedSecretPASERK,
} from '../../index.ts'

type PasswordUnwrapLimits = { maxMemory?: number; maxPasses?: number; maxParallelism?: number }

export type { Argon2idParameters }

export type ModernVersion = 2 | 4

type ImplicitAssertionParameters<V extends ModernVersion> = [V] extends [1 | 2]
  ? []
  : [V] extends [3 | 4]
    ? [implicitAssertion: Uint8Array]
    : [implicitAssertion?: Uint8Array]

export type PlainPaserkType = 'local' | 'public' | 'secret'

export type PaserkIdType = 'lid' | 'pid' | 'sid'

export type PaserkWrapType = 'local-wrap' | 'secret-wrap'

type LocalIdInput<V extends ModernVersion> =
  | LocalPASERK<V>
  | PasswordWrappedLocalPASERK<V>
  | SealedLocalPASERK<V>
  | WrappedLocalPASERK<V, string>
type SecretIdInput<V extends ModernVersion> =
  SecretPASERK<V> | PasswordWrappedSecretPASERK<V> | WrappedSecretPASERK<V, string>

export interface PasetoLocalResult {
  payload: Uint8Array
  footer: Uint8Array
}

export interface PasswordWrapParameters {
  memory: number
  passes: number
  parallelism: number
  salt: Uint8Array
  nonce: Uint8Array
}

/** Random source and Argon2id implementation used by private Noble capability maps. */
export interface NobleSuiteOptions {
  /** Random-byte source. Defaults to the source used by `@noble/hashes`. */
  randomBytes?: (length: number) => Uint8Array
  /** Argon2id factory. Defaults to the package's Web Cryptography implementation. */
  argon2id?: Argon2idFactory
}

type NobleKeyRole = 'local' | 'public' | 'secret' | 'wrapping' | 'sealing-public' | 'sealing-secret'

interface NobleKeyData<V extends ModernVersion = ModernVersion> {
  readonly version: V
  readonly role: NobleKeyRole
  readonly material: Uint8Array
  readonly publicMaterial?: Uint8Array | undefined
  readonly extractable: boolean
}

const keyData: WeakMap<object, NobleKeyData> = new WeakMap()
const keyConstruction: symbol = Symbol('Noble PASETO key construction')

/** Opaque structural key returned by the private Noble reference factories. */
export class NobleKey<
  V extends ModernVersion = ModernVersion,
  R extends NobleKeyRole = NobleKeyRole,
> implements Key {
  readonly #brand: undefined
  readonly algorithm: { readonly name: string }
  readonly extractable: boolean
  readonly type: R

  constructor(
    construction: symbol,
    version: V,
    role: R,
    material: Uint8Array,
    extractable: boolean,
    publicMaterial?: Uint8Array,
  ) {
    if (construction !== keyConstruction) throw new TypeError('Noble keys are opaque')
    this.#brand = undefined
    void this.#brand
    this.algorithm = {
      name: role.startsWith('sealing-') ? `PASERK k${version}.seal` : `PASETO v${version}`,
    }
    this.extractable = extractable
    this.type = role
    keyData.set(this, {
      version,
      role,
      material: copy(material),
      publicMaterial: publicMaterial === undefined ? undefined : copy(publicMaterial),
      extractable,
    })
  }
}

/** Key representations used by the private Noble `local` factories. */
export interface NobleLocalKeyTypes<V extends ModernVersion = ModernVersion> {
  readonly local: NobleKey<V, 'local'>
  readonly wrapping: NobleKey<V, 'wrapping'>
  readonly sealingPublic: NobleKey<V, 'sealing-public'>
  readonly sealingSecret: NobleKey<V, 'sealing-secret'>
}

/** Key representations used by the private Noble `public` factories. */
export interface NoblePublicKeyTypes<V extends ModernVersion = ModernVersion> {
  readonly public: NobleKey<V, 'public'>
  readonly secret: NobleKey<V, 'secret'>
  readonly wrapping: NobleKey<V, 'wrapping'>
}

const encoder: TextEncoder = new TextEncoder()

function bytes(input: string): Uint8Array {
  return encoder.encode(input)
}

function checkBytes(input: Uint8Array, label: string, length?: number): void {
  if (!(input instanceof Uint8Array)) throw new TypeError(`"${label}" must be a Uint8Array`)
  if (length !== undefined && input.byteLength !== length) {
    throw new TypeError(`"${label}" must be ${length} bytes`)
  }
}

function copy(input: Uint8Array): Uint8Array {
  checkBytes(input, 'input')
  return Uint8Array.from(input)
}

function concat(...inputs: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(inputs.reduce((length, input) => length + input.byteLength, 0))
  let offset = 0
  for (const input of inputs) {
    output.set(input, offset)
    offset += input.byteLength
  }
  return output
}

function fallbackToBase64url(input: Uint8Array): string {
  let binary = ''
  for (const value of input) binary += String.fromCharCode(value)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function fallbackFromBase64url(input: string): Uint8Array {
  const base64 = input.replaceAll('-', '+').replaceAll('_', '/')
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0))
}

function base64url(input: Uint8Array): string {
  // @ts-ignore New typed-array Base64 API with an atob/btoa-only fallback.
  return (
    input.toBase64?.({ alphabet: 'base64url', omitPadding: true }) || fallbackToBase64url(input)
  )
}

function decodeBase64url(input: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(input) || input.length % 4 === 1) {
    throw new TypeError('Invalid base64url')
  }
  // @ts-ignore New typed-array Base64 API with an atob/btoa-only fallback.
  const output =
    Uint8Array.fromBase64?.(input, { alphabet: 'base64url' }) || fallbackFromBase64url(input)
  if (base64url(output) !== input) throw new TypeError('Non-canonical base64url')
  return output
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.byteLength ^ right.byteLength
  const length = Math.max(left.byteLength, right.byteLength)
  for (let index = 0; index < length; index++) {
    difference |= (left[index % left.byteLength] ?? 0) ^ (right[index % right.byteLength] ?? 0)
  }
  return difference === 0
}

function assertLength(input: Uint8Array, length: number, label: string): void {
  checkBytes(input, label, length)
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`"${label}" must be a positive safe integer`)
  }
  return value
}

function generatedBytes(source: (length: number) => Uint8Array, length: number): Uint8Array {
  const output = source(length)
  checkBytes(output, 'randomBytes result', length)
  return copy(output)
}

function getKey<V extends ModernVersion, R extends NobleKeyRole>(
  key: NobleKey<V, R>,
  version: V,
  role: R,
  label: string,
): NobleKeyData<V> {
  const data = keyData.get(key)
  if (data?.version !== version || data.role !== role) {
    throw new InvalidKeyError(`"${label}" is not a Noble k${version} ${role} key`)
  }
  return data as NobleKeyData<V>
}

function requireExtractable(data: NobleKeyData): void {
  if (!data.extractable) throw new InvalidKeyError('Key is not extractable')
}

function newKey<V extends ModernVersion, R extends NobleKeyRole>(
  version: V,
  role: R,
  material: Uint8Array,
  extractable: boolean,
  publicMaterial?: Uint8Array,
): NobleKey<V, R> {
  return new NobleKey(keyConstruction, version, role, material, extractable, publicMaterial)
}

function assertPlaintextLength(type: PaserkWrapType, plaintext: Uint8Array): void {
  assertLength(plaintext, type === 'local-wrap' ? 32 : 64, `${type} plaintext`)
}

function encodeUint32(value: number): Uint8Array {
  const output = new Uint8Array(4)
  new DataView(output.buffer).setUint32(0, value)
  return output
}

function encodeUint64(value: number): Uint8Array {
  const output = new Uint8Array(8)
  new DataView(output.buffer).setBigUint64(0, BigInt(value))
  return output
}

function readUint32(input: Uint8Array, offset: number): number {
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint32(offset)
}

function readUint64(input: Uint8Array, offset: number): number {
  const value = new DataView(input.buffer, input.byteOffset, input.byteLength).getBigUint64(offset)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new RangeError('Integer exceeds safe range')
  return Number(value)
}

function le64(value: number): Uint8Array {
  const output = new Uint8Array(8)
  new DataView(output.buffer).setBigUint64(0, BigInt(value), true)
  return output
}

function pae(pieces: readonly Uint8Array[]): Uint8Array {
  return concat(le64(pieces.length), ...pieces.flatMap((piece) => [le64(piece.byteLength), piece]))
}

function parseToken(
  token: string,
  expectedHeader: string,
): { body: Uint8Array; footer: Uint8Array } {
  const segments = token.split('.')
  if (
    (segments.length !== 3 && segments.length !== 4) ||
    `${segments[0]}.${segments[1]}.` !== expectedHeader ||
    !segments[2] ||
    (segments.length === 4 && !segments[3])
  ) {
    throw new TypeError('Invalid token')
  }
  return {
    body: decodeBase64url(segments[2]),
    footer: segments[3] ? decodeBase64url(segments[3]) : new Uint8Array(),
  }
}

function formatToken(header: string, body: Uint8Array, footer: Uint8Array): string {
  const token = `${header}${base64url(body)}`
  return footer.byteLength === 0 ? token : `${token}.${base64url(footer)}`
}

export function blake2b(input: Uint8Array, outputLength: number, key?: Uint8Array): Uint8Array {
  return nobleBlake2b(
    input,
    key === undefined ? { dkLen: outputLength } : { dkLen: outputLength, key },
  )
}

export function xchacha20(
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  counter = 0,
): Uint8Array {
  return nobleXChaCha20(key, nonce, input, undefined, counter)
}

export function xchacha20poly1305Encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Uint8Array {
  return nobleXChaCha20Poly1305(key, nonce, additionalData).encrypt(plaintext)
}

export function xchacha20poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  additionalData: Uint8Array,
): Uint8Array {
  return nobleXChaCha20Poly1305(key, nonce, additionalData).decrypt(ciphertext)
}

export function ed25519PublicToX25519(publicKey: Uint8Array): Uint8Array {
  assertLength(publicKey, 32, 'Ed25519 public key')
  return ed25519.utils.toMontgomery(publicKey)
}

export function ed25519SecretToX25519(secretKey: Uint8Array): Uint8Array {
  if (secretKey.byteLength !== 32 && secretKey.byteLength !== 64) {
    throw new TypeError('Ed25519 secret key must be 32 or 64 bytes')
  }
  return ed25519.utils.toMontgomerySecret(secretKey.subarray(0, 32))
}

export async function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  { memory, passes, parallelism, length }: Readonly<Argon2idParameters>,
): Promise<Uint8Array> {
  if (memory % 1024 !== 0) {
    throw new RangeError('Argon2id memory must be a whole number of kibibytes')
  }
  return await argon2idAsync(password, salt, {
    m: memory / 1024,
    t: passes,
    p: parallelism,
    dkLen: length,
  })
}

/** Repository-only Argon2id factory backed by `@noble/hashes`. */
export const KDF_ARGON2ID_NOBLE: Argon2idFactory = function (): Readonly<Argon2id> {
  return Object.freeze({ type: 'KDF' as const, name: 'Argon2id' as const, Derive: argon2id })
}

function encryptPasetoLocalPayload(
  version: ModernVersion,
  key: Uint8Array,
  payload: Uint8Array,
  nonce: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  implicitAssertion: Uint8Array = new Uint8Array(),
): Uint8Array {
  assertLength(key, 32, 'PASETO local key')
  const header = bytes(`v${version}.local.`)

  if (version === 2) {
    assertLength(nonce, 24, 'PASETO v2 pre-authentication nonce')
    const derivedNonce = blake2b(payload, 24, nonce)
    const ciphertext = xchacha20poly1305Encrypt(
      key,
      derivedNonce,
      payload,
      pae([header, derivedNonce, footer]),
    )
    return concat(derivedNonce, ciphertext)
  }

  assertLength(nonce, 32, 'PASETO v4 nonce')
  const material = blake2b(concat(bytes('paseto-encryption-key'), nonce), 56, key)
  const ciphertext = xchacha20(material.subarray(0, 32), material.subarray(32), payload)
  const authenticationKey = blake2b(concat(bytes('paseto-auth-key-for-aead'), nonce), 32, key)
  const tag = blake2b(
    pae([header, nonce, ciphertext, footer, implicitAssertion]),
    32,
    authenticationKey,
  )
  return concat(nonce, ciphertext, tag)
}

function decryptPasetoLocalPayload(
  version: ModernVersion,
  key: Uint8Array,
  body: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  implicitAssertion: Uint8Array = new Uint8Array(),
): Uint8Array {
  assertLength(key, 32, 'PASETO local key')
  const headerString = `v${version}.local.`
  const header = bytes(headerString)

  if (version === 2) {
    if (body.byteLength < 40) throw new TypeError('Invalid PASETO v2.local payload')
    const nonce = body.subarray(0, 24)
    const ciphertext = body.subarray(24)
    return xchacha20poly1305Decrypt(key, nonce, ciphertext, pae([header, nonce, footer]))
  }

  if (body.byteLength < 64) throw new TypeError('Invalid PASETO v4.local payload')
  const nonce = body.subarray(0, 32)
  const ciphertext = body.subarray(32, -32)
  const tag = body.subarray(-32)
  const authenticationKey = blake2b(concat(bytes('paseto-auth-key-for-aead'), nonce), 32, key)
  const expectedTag = blake2b(
    pae([header, nonce, ciphertext, footer, implicitAssertion]),
    32,
    authenticationKey,
  )
  if (!equal(tag, expectedTag)) throw new Error('Invalid PASETO authentication tag')
  const material = blake2b(concat(bytes('paseto-encryption-key'), nonce), 56, key)
  return xchacha20(material.subarray(0, 32), material.subarray(32), ciphertext)
}

export function encryptPasetoLocal(
  version: ModernVersion,
  key: Uint8Array,
  payload: Uint8Array,
  nonce: Uint8Array,
  footer: Uint8Array = new Uint8Array(),
  implicitAssertion: Uint8Array = new Uint8Array(),
): string {
  return formatToken(
    `v${version}.local.`,
    encryptPasetoLocalPayload(version, key, payload, nonce, footer, implicitAssertion),
    footer,
  )
}

export function decryptPasetoLocal(
  version: ModernVersion,
  key: Uint8Array,
  token: string,
  implicitAssertion: Uint8Array = new Uint8Array(),
): PasetoLocalResult {
  const header = `v${version}.local.`
  const { body, footer } = parseToken(token, header)
  return {
    payload: decryptPasetoLocalPayload(version, key, body, footer, implicitAssertion),
    footer,
  }
}

export function serializeModernPaserk(
  version: ModernVersion,
  type: PlainPaserkType,
  key: Uint8Array,
): string {
  assertLength(key, type === 'secret' ? 64 : 32, `k${version}.${type} key`)
  return `k${version}.${type}.${base64url(key)}`
}

export function modernPaserkId(version: ModernVersion, type: PaserkIdType, paserk: string): string {
  validatePaserkIdInput(version, type, paserk)
  const header = `k${version}.${type}.`
  return `${header}${base64url(blake2b(concat(bytes(header), bytes(paserk)), 33))}`
}

function validatePaserkIdInput(version: ModernVersion, type: PaserkIdType, paserk: string): void {
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')

  const standard = (...types: readonly string[]): boolean => {
    for (const inputType of types) {
      const header = `k${version}.${inputType}.`
      if (!paserk.startsWith(header)) continue
      const payload = paserk.slice(header.length)
      if (payload === '' || payload.includes('.')) return false
      try {
        decodeBase64url(payload)
        return true
      } catch (cause) {
        throw new InvalidPASERKError('Invalid PASERK payload', { cause })
      }
    }
    return false
  }
  const wrapped = (inputType: 'local-wrap' | 'secret-wrap'): boolean => {
    const header = `k${version}.${inputType}.`
    if (!paserk.startsWith(header)) return false
    const data = paserk.slice(header.length)
    const delimiter = data.indexOf('.')
    if (delimiter < 1) return false
    const prefix = data.slice(0, delimiter)
    const encryptedKey = data.slice(delimiter + 1)
    return (
      /^[a-z0-9-]+$/u.test(prefix) && encryptedKey !== '' && /^[\x00-\x7f]+$/u.test(encryptedKey)
    )
  }

  const valid =
    type === 'lid'
      ? standard('local', 'local-pw', 'seal') || wrapped('local-wrap')
      : type === 'pid'
        ? standard('public')
        : standard('secret', 'secret-pw') || wrapped('secret-wrap')
  if (!valid) throw new InvalidPASERKError(`Expected a k${version}.${type}. compatible PASERK`)
}

export function wrapPaserkPie(
  version: ModernVersion,
  type: PaserkWrapType,
  plaintext: Uint8Array,
  wrappingKey: Uint8Array,
  nonce: Uint8Array,
): string {
  assertPlaintextLength(type, plaintext)
  assertLength(wrappingKey, 32, 'PASERK wrapping key')
  assertLength(nonce, 32, 'PASERK pie nonce')
  const header = `k${version}.${type}.pie.`
  const encryptionMaterial = blake2b(concat(Uint8Array.of(0x80), nonce), 56, wrappingKey)
  const ciphertext = xchacha20(
    encryptionMaterial.subarray(0, 32),
    encryptionMaterial.subarray(32),
    plaintext,
  )
  const authenticationKey = blake2b(concat(Uint8Array.of(0x81), nonce), 32, wrappingKey)
  const tag = blake2b(concat(bytes(header), nonce, ciphertext), 32, authenticationKey)
  return `${header}${base64url(concat(tag, nonce, ciphertext))}`
}

export function unwrapPaserkPie(
  version: ModernVersion,
  type: PaserkWrapType,
  paserk: string,
  wrappingKey: Uint8Array,
): Uint8Array {
  assertLength(wrappingKey, 32, 'PASERK wrapping key')
  const header = `k${version}.${type}.pie.`
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (!paserk.startsWith(header)) throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  let body: Uint8Array
  try {
    body = decodeBase64url(paserk.slice(header.length))
  } catch (cause) {
    throw new InvalidPASERKError('Invalid PASERK payload', { cause })
  }
  const plaintextLength = type === 'local-wrap' ? 32 : 64
  if (body.byteLength !== 64 + plaintextLength) {
    throw new InvalidPASERKError('Invalid wrapped PASERK length')
  }
  const tag = body.subarray(0, 32)
  const nonce = body.subarray(32, 64)
  const ciphertext = body.subarray(64)
  const authenticationKey = blake2b(concat(Uint8Array.of(0x81), nonce), 32, wrappingKey)
  const expectedTag = blake2b(concat(bytes(header), nonce, ciphertext), 32, authenticationKey)
  if (!equal(tag, expectedTag)) throw new InvalidPASERKError('Wrapped PASERK authentication failed')
  const encryptionMaterial = blake2b(concat(Uint8Array.of(0x80), nonce), 56, wrappingKey)
  const plaintext = xchacha20(
    encryptionMaterial.subarray(0, 32),
    encryptionMaterial.subarray(32),
    ciphertext,
  )
  assertPlaintextLength(type, plaintext)
  return plaintext
}

async function wrapPaserkPasswordUsing(
  version: ModernVersion,
  type: PaserkWrapType,
  plaintext: Uint8Array,
  password: Uint8Array,
  parameters: Readonly<PasswordWrapParameters>,
  implementation: Readonly<Argon2id>,
): Promise<string> {
  assertPlaintextLength(type, plaintext)
  assertLength(parameters.salt, 16, 'PASERK password salt')
  assertLength(parameters.nonce, 24, 'PASERK password nonce')
  const header = `k${version}.${type === 'local-wrap' ? 'local-pw' : 'secret-pw'}.`
  const preKey = await implementation.Derive(password, parameters.salt, {
    memory: parameters.memory,
    passes: parameters.passes,
    parallelism: parameters.parallelism,
    length: 32,
  })
  assertLength(preKey, 32, 'Argon2id result')
  const encryptionKey = blake2b(concat(Uint8Array.of(0xff), preKey), 32)
  const authenticationKey = blake2b(concat(Uint8Array.of(0xfe), preKey), 32)
  const ciphertext = xchacha20(encryptionKey, parameters.nonce, plaintext)
  const contents = concat(
    parameters.salt,
    encodeUint64(parameters.memory),
    encodeUint32(parameters.passes),
    encodeUint32(parameters.parallelism),
    parameters.nonce,
    ciphertext,
  )
  const tag = blake2b(concat(bytes(header), contents), 32, authenticationKey)
  return `${header}${base64url(concat(contents, tag))}`
}

async function unwrapPaserkPasswordUsing(
  version: ModernVersion,
  type: PaserkWrapType,
  paserk: string,
  password: Uint8Array,
  implementation: Readonly<Argon2id>,
): Promise<Uint8Array> {
  const header = `k${version}.${type === 'local-wrap' ? 'local-pw' : 'secret-pw'}.`
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (!paserk.startsWith(header)) throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  let body: Uint8Array
  try {
    body = decodeBase64url(paserk.slice(header.length))
  } catch (cause) {
    throw new InvalidPASERKError('Invalid password-wrapped PASERK payload', { cause })
  }
  const plaintextLength = type === 'local-wrap' ? 32 : 64
  if (body.byteLength !== 88 + plaintextLength) {
    throw new InvalidPASERKError('Invalid password-wrapped PASERK length')
  }
  const salt = body.subarray(0, 16)
  const memory = readUint64(body, 16)
  const passes = readUint32(body, 24)
  const parallelism = readUint32(body, 28)
  const nonce = body.subarray(32, 56)
  const ciphertext = body.subarray(56, -32)
  const tag = body.subarray(-32)
  const preKey = await implementation.Derive(password, salt, {
    memory,
    passes,
    parallelism,
    length: 32,
  })
  assertLength(preKey, 32, 'Argon2id result')
  const authenticationKey = blake2b(concat(Uint8Array.of(0xfe), preKey), 32)
  const expectedTag = blake2b(concat(bytes(header), body.subarray(0, -32)), 32, authenticationKey)
  if (!equal(tag, expectedTag)) {
    throw new InvalidPASERKError('Password-wrapped PASERK authentication failed')
  }
  const encryptionKey = blake2b(concat(Uint8Array.of(0xff), preKey), 32)
  const plaintext = xchacha20(encryptionKey, nonce, ciphertext)
  assertPlaintextLength(type, plaintext)
  return plaintext
}

/** Wrap a modern PASERK with the repository-only Noble Argon2id reference. */
export async function wrapPaserkPassword(
  version: ModernVersion,
  type: PaserkWrapType,
  plaintext: Uint8Array,
  password: Uint8Array,
  parameters: Readonly<PasswordWrapParameters>,
): Promise<string> {
  return await wrapPaserkPasswordUsing(
    version,
    type,
    plaintext,
    password,
    parameters,
    KDF_ARGON2ID_NOBLE(),
  )
}

/** Open a modern PASERK with the repository-only Noble Argon2id reference. */
export async function unwrapPaserkPassword(
  version: ModernVersion,
  type: PaserkWrapType,
  paserk: string,
  password: Uint8Array,
): Promise<Uint8Array> {
  return await unwrapPaserkPasswordUsing(version, type, paserk, password, KDF_ARGON2ID_NOBLE())
}

export function sealModernPaserk(
  version: ModernVersion,
  plaintext: Uint8Array,
  sealingPublicKey: Uint8Array,
  ephemeralSecretKey: Uint8Array,
): string {
  assertLength(plaintext, 32, 'PASERK sealed local key')
  assertLength(sealingPublicKey, 32, 'PASERK sealing public key')
  assertLength(ephemeralSecretKey, 32, 'X25519 ephemeral secret key')
  const header = `k${version}.seal.`
  const recipientPublicKey = ed25519PublicToX25519(sealingPublicKey)
  const ephemeralPublicKey = x25519.getPublicKey(ephemeralSecretKey)
  const sharedSecret = x25519.getSharedSecret(ephemeralSecretKey, recipientPublicKey)
  const encryptionKey = blake2b(
    concat(
      Uint8Array.of(0x01),
      bytes(header),
      sharedSecret,
      ephemeralPublicKey,
      recipientPublicKey,
    ),
    32,
  )
  const authenticationKey = blake2b(
    concat(
      Uint8Array.of(0x02),
      bytes(header),
      sharedSecret,
      ephemeralPublicKey,
      recipientPublicKey,
    ),
    32,
  )
  const nonce = blake2b(concat(ephemeralPublicKey, recipientPublicKey), 24)
  const ciphertext = xchacha20(encryptionKey, nonce, plaintext)
  const tag = blake2b(concat(bytes(header), ephemeralPublicKey, ciphertext), 32, authenticationKey)
  return `${header}${base64url(concat(tag, ephemeralPublicKey, ciphertext))}`
}

export function unsealModernPaserk(
  version: ModernVersion,
  paserk: string,
  sealingSecretKey: Uint8Array,
): Uint8Array {
  assertLength(sealingSecretKey, 64, 'PASERK sealing secret key')
  const header = `k${version}.seal.`
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  if (!paserk.startsWith(header)) throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  let body: Uint8Array
  try {
    body = decodeBase64url(paserk.slice(header.length))
  } catch (cause) {
    throw new InvalidPASERKError('Invalid sealed PASERK payload', { cause })
  }
  if (body.byteLength !== 96) throw new InvalidPASERKError('Invalid sealed PASERK length')
  const tag = body.subarray(0, 32)
  const ephemeralPublicKey = body.subarray(32, 64)
  const ciphertext = body.subarray(64)
  const seed = sealingSecretKey.subarray(0, 32)
  const edPublicKey = sealingSecretKey.subarray(32)
  if (!equal(ed25519.getPublicKey(seed), edPublicKey)) {
    throw new TypeError('Ed25519 secret key has an inconsistent public key')
  }
  const recipientPublicKey = ed25519PublicToX25519(edPublicKey)
  const recipientSecretKey = ed25519SecretToX25519(seed)
  const sharedSecret = x25519.getSharedSecret(recipientSecretKey, ephemeralPublicKey)
  const authenticationKey = blake2b(
    concat(
      Uint8Array.of(0x02),
      bytes(header),
      sharedSecret,
      ephemeralPublicKey,
      recipientPublicKey,
    ),
    32,
  )
  const expectedTag = blake2b(
    concat(bytes(header), ephemeralPublicKey, ciphertext),
    32,
    authenticationKey,
  )
  if (!equal(tag, expectedTag)) throw new InvalidPASERKError('Sealed PASERK authentication failed')
  const encryptionKey = blake2b(
    concat(
      Uint8Array.of(0x01),
      bytes(header),
      sharedSecret,
      ephemeralPublicKey,
      recipientPublicKey,
    ),
    32,
  )
  const nonce = blake2b(concat(ephemeralPublicKey, recipientPublicKey), 24)
  return xchacha20(encryptionKey, nonce, ciphertext)
}

function parseModernPaserk(
  version: ModernVersion,
  type: PlainPaserkType,
  paserk: string,
): Uint8Array {
  if (typeof paserk !== 'string') throw new TypeError('"paserk" must be a string')
  const header = `k${version}.${type}.`
  if (!paserk.startsWith(header) || paserk.slice(header.length).includes('.')) {
    throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  }
  try {
    return decodeBase64url(paserk.slice(header.length))
  } catch (cause) {
    throw new InvalidPASERKError('Invalid PASERK payload', { cause })
  }
}

function checkEd25519PublicKey(material: Uint8Array, label: string): void {
  assertLength(material, 32, label)
  try {
    ed25519.Point.fromBytes(material)
  } catch (cause) {
    throw new InvalidKeyError(`Invalid ${label}`, { cause })
  }
}

function checkEd25519SecretKey(material: Uint8Array, label: string): Uint8Array {
  assertLength(material, 64, label)
  const publicMaterial = ed25519.getPublicKey(material.subarray(0, 32))
  if (!equal(publicMaterial, material.subarray(32))) {
    throw new InvalidKeyError(`${label} has an inconsistent public key`)
  }
  return publicMaterial
}

function passwordOptions<V extends ModernVersion>(
  options: PasswordWrapOptions<V> = {},
): { memory: number; passes: number; parallelism: number } {
  // Every ModernVersion uses the Argon2id option family, but TypeScript defers conditional types
  // over a generic parameter even when its constraint proves that fact.
  const argon2id = options as PasswordWrapOptions<ModernVersion>
  const memory = positiveInteger(argon2id.memory ?? 64 * 1024 * 1024, 'memory')
  const passes = positiveInteger(argon2id.passes ?? 2, 'passes')
  const parallelism = positiveInteger(argon2id.parallelism ?? 1, 'parallelism')
  if (memory % 1024 !== 0) {
    throw new RangeError('"memory" must be a whole number of kibibytes')
  }
  return { memory, passes, parallelism }
}

function passwordLimits(
  memory: number,
  passes: number,
  parallelism: number,
  limits: PasswordUnwrapLimits,
): void {
  const maxMemory = positiveInteger(limits.maxMemory ?? 1024 * 1024 * 1024, 'maxMemory')
  const maxPasses = positiveInteger(limits.maxPasses ?? 10, 'maxPasses')
  const maxParallelism = positiveInteger(limits.maxParallelism ?? 16, 'maxParallelism')
  if (
    memory === 0 ||
    memory % 1024 !== 0 ||
    memory > maxMemory ||
    passes === 0 ||
    passes > maxPasses ||
    parallelism === 0 ||
    parallelism > maxParallelism
  ) {
    throw new InvalidPASERKError('Argon2id parameters exceed configured limits')
  }
}

function modernPasswordParameters(
  paserk: string,
  version: ModernVersion,
  type: PaserkWrapType,
): { memory: number; passes: number; parallelism: number } {
  const header = `k${version}.${type === 'local-wrap' ? 'local-pw' : 'secret-pw'}.`
  if (!paserk.startsWith(header)) throw new InvalidPASERKError(`Expected a ${header} PASERK`)
  let body: Uint8Array
  try {
    body = decodeBase64url(paserk.slice(header.length))
  } catch (cause) {
    throw new InvalidPASERKError('Invalid password-wrapped PASERK payload', { cause })
  }
  const plaintextLength = type === 'local-wrap' ? 32 : 64
  if (body.byteLength !== 88 + plaintextLength) {
    throw new InvalidPASERKError('Invalid password-wrapped PASERK length')
  }
  return {
    memory: readUint64(body, 16),
    passes: readUint32(body, 24),
    parallelism: readUint32(body, 28),
  }
}

function validateArgon2id(factory: Argon2idFactory): Readonly<Argon2id> {
  if (typeof factory !== 'function') throw new TypeError('"argon2id" must be a factory')
  const implementation = factory()
  if (
    implementation === null ||
    typeof implementation !== 'object' ||
    implementation.type !== 'KDF' ||
    typeof implementation.Derive !== 'function'
  ) {
    throw new TypeError('Invalid Argon2id implementation')
  }
  return implementation
}

class NobleLocalPASERK<V extends ModernVersion> {
  readonly #version: V
  readonly #randomBytes: (length: number) => Uint8Array
  readonly #argon2id: Readonly<Argon2id>

  constructor(
    version: V,
    randomBytes: (length: number) => Uint8Array,
    argon2id: Readonly<Argon2id>,
  ) {
    this.#version = version
    this.#randomBytes = randomBytes
    this.#argon2id = argon2id
  }

  async Serialize(key: NobleKey<V, 'local'>): Promise<LocalPASERK<V>> {
    const data = getKey(key, this.#version, 'local', 'key')
    requireExtractable(data)
    return serializeModernPaserk(this.#version, 'local', data.material) as LocalPASERK<V>
  }

  async Deserialize(paserk: LocalPASERK<V>, options?: KeyOptions): Promise<NobleKey<V, 'local'>> {
    const material = parseModernPaserk(this.#version, 'local', paserk)
    assertLength(material, 32, 'PASERK local key')
    return newKey(this.#version, 'local', material, options?.extractable ?? false)
  }

  async ID(paserk: LocalIdInput<V>): Promise<LocalIdPASERK<V>> {
    return modernPaserkId(this.#version, 'lid', paserk) as LocalIdPASERK<V>
  }

  async GenerateWrappingKey(options?: KeyOptions): Promise<NobleKey<V, 'wrapping'>> {
    return newKey(
      this.#version,
      'wrapping',
      generatedBytes(this.#randomBytes, 32),
      options?.extractable ?? false,
    )
  }

  async ImportWrappingKey(
    material: Uint8Array,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'wrapping'>> {
    assertLength(material, 32, 'PASERK wrapping key')
    return newKey(this.#version, 'wrapping', material, options?.extractable ?? false)
  }

  async ExportWrappingKey(key: NobleKey<V, 'wrapping'>): Promise<Uint8Array> {
    const data = getKey(key, this.#version, 'wrapping', 'key')
    requireExtractable(data)
    return copy(data.material)
  }

  async Wrap(
    key: NobleKey<V, 'local'>,
    wrappingKey: NobleKey<V, 'wrapping'>,
  ): Promise<WrappedLocalPASERK<V, 'pie'>> {
    const source = getKey(key, this.#version, 'local', 'key')
    requireExtractable(source)
    return wrapPaserkPie(
      this.#version,
      'local-wrap',
      source.material,
      getKey(wrappingKey, this.#version, 'wrapping', 'wrappingKey').material,
      generatedBytes(this.#randomBytes, 32),
    ) as WrappedLocalPASERK<V, 'pie'>
  }

  async Unwrap(
    paserk: WrappedLocalPASERK<V, 'pie'>,
    wrappingKey: NobleKey<V, 'wrapping'>,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'local'>> {
    try {
      const material = unwrapPaserkPie(
        this.#version,
        'local-wrap',
        paserk,
        getKey(wrappingKey, this.#version, 'wrapping', 'wrappingKey').material,
      )
      return newKey(this.#version, 'local', material, options?.extractable ?? false)
    } catch (cause) {
      if (cause instanceof InvalidKeyError || cause instanceof InvalidPASERKError) throw cause
      throw new InvalidPASERKError('Wrapped PASERK authentication failed', { cause })
    }
  }

  async WrapWithPassword(
    key: NobleKey<V, 'local'>,
    password: Uint8Array,
    options?: PasswordWrapOptions<V>,
  ): Promise<PasswordWrappedLocalPASERK<V>> {
    checkBytes(password, 'password')
    if (password.byteLength === 0) throw new TypeError('"password" must not be empty')
    const source = getKey(key, this.#version, 'local', 'key')
    requireExtractable(source)
    const parameters = passwordOptions(options)
    return (await wrapPaserkPasswordUsing(
      this.#version,
      'local-wrap',
      source.material,
      password,
      {
        ...parameters,
        salt: generatedBytes(this.#randomBytes, 16),
        nonce: generatedBytes(this.#randomBytes, 24),
      },
      this.#argon2id,
    )) as PasswordWrappedLocalPASERK<V>
  }

  async UnwrapWithPassword(
    paserk: PasswordWrappedLocalPASERK<V>,
    password: Uint8Array,
    limits: PasswordUnwrapLimits = {},
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'local'>> {
    checkBytes(password, 'password')
    if (password.byteLength === 0) throw new TypeError('"password" must not be empty')
    const parameters = modernPasswordParameters(paserk, this.#version, 'local-wrap')
    passwordLimits(parameters.memory, parameters.passes, parameters.parallelism, limits)
    try {
      return newKey(
        this.#version,
        'local',
        await unwrapPaserkPasswordUsing(
          this.#version,
          'local-wrap',
          paserk,
          password,
          this.#argon2id,
        ),
        options?.extractable ?? false,
      )
    } catch (cause) {
      if (cause instanceof InvalidPASERKError) throw cause
      throw new InvalidPASERKError('Password-wrapped PASERK authentication failed', { cause })
    }
  }

  async GenerateSealingKeyPair(
    options?: KeyOptions,
  ): Promise<KeyPair<NobleKey<V, 'sealing-public'>, NobleKey<V, 'sealing-secret'>>> {
    const seed = generatedBytes(this.#randomBytes, 32)
    const publicMaterial = ed25519.getPublicKey(seed)
    const secretMaterial = concat(seed, publicMaterial)
    return {
      publicKey: newKey(this.#version, 'sealing-public', publicMaterial, true),
      secretKey: newKey(
        this.#version,
        'sealing-secret',
        secretMaterial,
        options?.extractable ?? false,
        publicMaterial,
      ),
    }
  }

  async ImportSealingPublicKey(material: Uint8Array): Promise<NobleKey<V, 'sealing-public'>> {
    checkEd25519PublicKey(material, 'PASERK sealing public key')
    return newKey(this.#version, 'sealing-public', material, true)
  }

  async ImportSealingSecretKey(
    material: Uint8Array,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'sealing-secret'>> {
    const publicMaterial = checkEd25519SecretKey(material, 'PASERK sealing secret key')
    return newKey(
      this.#version,
      'sealing-secret',
      material,
      options?.extractable ?? false,
      publicMaterial,
    )
  }

  async ExportSealingPublicKey(key: NobleKey<V, 'sealing-public'>): Promise<Uint8Array> {
    return copy(getKey(key, this.#version, 'sealing-public', 'key').material)
  }

  async ExportSealingSecretKey(key: NobleKey<V, 'sealing-secret'>): Promise<Uint8Array> {
    const data = getKey(key, this.#version, 'sealing-secret', 'key')
    requireExtractable(data)
    return copy(data.material)
  }

  async Seal(
    key: NobleKey<V, 'local'>,
    recipient: NobleKey<V, 'sealing-public'>,
  ): Promise<SealedLocalPASERK<V>> {
    const source = getKey(key, this.#version, 'local', 'key')
    requireExtractable(source)
    return sealModernPaserk(
      this.#version,
      source.material,
      getKey(recipient, this.#version, 'sealing-public', 'recipient').material,
      generatedBytes(this.#randomBytes, 32),
    ) as SealedLocalPASERK<V>
  }

  async Unseal(
    paserk: SealedLocalPASERK<V>,
    recipient: NobleKey<V, 'sealing-secret'>,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'local'>> {
    try {
      return newKey(
        this.#version,
        'local',
        unsealModernPaserk(
          this.#version,
          paserk,
          getKey(recipient, this.#version, 'sealing-secret', 'recipient').material,
        ),
        options?.extractable ?? false,
      )
    } catch (cause) {
      if (cause instanceof InvalidKeyError || cause instanceof InvalidPASERKError) throw cause
      throw new InvalidPASERKError('Sealed PASERK authentication failed', { cause })
    }
  }
}

class NoblePublicPASERK<V extends ModernVersion> {
  readonly #version: V
  readonly #randomBytes: (length: number) => Uint8Array
  readonly #argon2id: Readonly<Argon2id>

  constructor(
    version: V,
    randomBytes: (length: number) => Uint8Array,
    argon2id: Readonly<Argon2id>,
  ) {
    this.#version = version
    this.#randomBytes = randomBytes
    this.#argon2id = argon2id
  }

  async SerializePublic(key: NobleKey<V, 'public'>): Promise<PublicPASERK<V>> {
    return serializeModernPaserk(
      this.#version,
      'public',
      getKey(key, this.#version, 'public', 'key').material,
    ) as PublicPASERK<V>
  }

  async DeserializePublic(paserk: PublicPASERK<V>): Promise<NobleKey<V, 'public'>> {
    const material = parseModernPaserk(this.#version, 'public', paserk)
    // PASERK raw serialization and identifiers are defined for every 32-byte string. Point
    // validation is deferred until an operation actually interprets this material as Ed25519.
    assertLength(material, 32, 'PASERK public key')
    return newKey(this.#version, 'public', material, true)
  }

  async SerializeSecret(key: NobleKey<V, 'secret'>): Promise<SecretPASERK<V>> {
    const data = getKey(key, this.#version, 'secret', 'key')
    requireExtractable(data)
    return serializeModernPaserk(this.#version, 'secret', data.material) as SecretPASERK<V>
  }

  async DeserializeSecret(
    paserk: SecretPASERK<V>,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'secret'>> {
    const material = parseModernPaserk(this.#version, 'secret', paserk)
    const publicMaterial = checkEd25519SecretKey(material, 'PASERK secret key')
    return newKey(this.#version, 'secret', material, options?.extractable ?? false, publicMaterial)
  }

  async GetPublicKey(key: NobleKey<V, 'secret'>): Promise<NobleKey<V, 'public'>> {
    const data = getKey(key, this.#version, 'secret', 'key')
    return newKey(this.#version, 'public', data.publicMaterial!, true)
  }

  async PublicID(paserk: PublicPASERK<V>): Promise<PublicIdPASERK<V>> {
    return modernPaserkId(this.#version, 'pid', paserk) as PublicIdPASERK<V>
  }

  async SecretID(paserk: SecretIdInput<V>): Promise<SecretIdPASERK<V>> {
    return modernPaserkId(this.#version, 'sid', paserk) as SecretIdPASERK<V>
  }

  async GenerateWrappingKey(options?: KeyOptions): Promise<NobleKey<V, 'wrapping'>> {
    return newKey(
      this.#version,
      'wrapping',
      generatedBytes(this.#randomBytes, 32),
      options?.extractable ?? false,
    )
  }

  async ImportWrappingKey(
    material: Uint8Array,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'wrapping'>> {
    assertLength(material, 32, 'PASERK wrapping key')
    return newKey(this.#version, 'wrapping', material, options?.extractable ?? false)
  }

  async ExportWrappingKey(key: NobleKey<V, 'wrapping'>): Promise<Uint8Array> {
    const data = getKey(key, this.#version, 'wrapping', 'key')
    requireExtractable(data)
    return copy(data.material)
  }

  async WrapSecret(
    key: NobleKey<V, 'secret'>,
    wrappingKey: NobleKey<V, 'wrapping'>,
  ): Promise<WrappedSecretPASERK<V, 'pie'>> {
    const source = getKey(key, this.#version, 'secret', 'key')
    requireExtractable(source)
    return wrapPaserkPie(
      this.#version,
      'secret-wrap',
      source.material,
      getKey(wrappingKey, this.#version, 'wrapping', 'wrappingKey').material,
      generatedBytes(this.#randomBytes, 32),
    ) as WrappedSecretPASERK<V, 'pie'>
  }

  async UnwrapSecret(
    paserk: WrappedSecretPASERK<V, 'pie'>,
    wrappingKey: NobleKey<V, 'wrapping'>,
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'secret'>> {
    try {
      const material = unwrapPaserkPie(
        this.#version,
        'secret-wrap',
        paserk,
        getKey(wrappingKey, this.#version, 'wrapping', 'wrappingKey').material,
      )
      const publicMaterial = checkEd25519SecretKey(material, 'unwrapped PASERK secret key')
      return newKey(
        this.#version,
        'secret',
        material,
        options?.extractable ?? false,
        publicMaterial,
      )
    } catch (cause) {
      if (cause instanceof InvalidKeyError || cause instanceof InvalidPASERKError) throw cause
      throw new InvalidPASERKError('Wrapped PASERK authentication failed', { cause })
    }
  }

  async WrapSecretWithPassword(
    key: NobleKey<V, 'secret'>,
    password: Uint8Array,
    options?: PasswordWrapOptions<V>,
  ): Promise<PasswordWrappedSecretPASERK<V>> {
    checkBytes(password, 'password')
    if (password.byteLength === 0) throw new TypeError('"password" must not be empty')
    const source = getKey(key, this.#version, 'secret', 'key')
    requireExtractable(source)
    const parameters = passwordOptions(options)
    return (await wrapPaserkPasswordUsing(
      this.#version,
      'secret-wrap',
      source.material,
      password,
      {
        ...parameters,
        salt: generatedBytes(this.#randomBytes, 16),
        nonce: generatedBytes(this.#randomBytes, 24),
      },
      this.#argon2id,
    )) as PasswordWrappedSecretPASERK<V>
  }

  async UnwrapSecretWithPassword(
    paserk: PasswordWrappedSecretPASERK<V>,
    password: Uint8Array,
    limits: PasswordUnwrapLimits = {},
    options?: KeyOptions,
  ): Promise<NobleKey<V, 'secret'>> {
    checkBytes(password, 'password')
    if (password.byteLength === 0) throw new TypeError('"password" must not be empty')
    const parameters = modernPasswordParameters(paserk, this.#version, 'secret-wrap')
    passwordLimits(parameters.memory, parameters.passes, parameters.parallelism, limits)
    try {
      const material = await unwrapPaserkPasswordUsing(
        this.#version,
        'secret-wrap',
        paserk,
        password,
        this.#argon2id,
      )
      const publicMaterial = checkEd25519SecretKey(material, 'password-unwrapped PASERK secret key')
      return newKey(
        this.#version,
        'secret',
        material,
        options?.extractable ?? false,
        publicMaterial,
      )
    } catch (cause) {
      if (cause instanceof InvalidPASERKError) throw cause
      throw new InvalidPASERKError('Password-wrapped PASERK authentication failed', { cause })
    }
  }
}

class NobleLocalProtocol<V extends ModernVersion> {
  readonly type = 'LOCAL' as const
  readonly version: V
  readonly PASERK: Readonly<NobleLocalPASERK<V>>
  readonly #randomBytes: (length: number) => Uint8Array

  constructor(version: V, options: Readonly<NobleSuiteOptions>) {
    this.version = version
    this.#randomBytes = options.randomBytes ?? nobleRandomBytes
    const argon2id = validateArgon2id(options.argon2id ?? KDF_ARGON2ID)
    this.PASERK = Object.freeze(new NobleLocalPASERK(version, this.#randomBytes, argon2id))
  }

  async GenerateKey(extractable: boolean): Promise<NobleKey<V, 'local'>> {
    return newKey(this.version, 'local', generatedBytes(this.#randomBytes, 32), extractable)
  }

  async Encrypt(
    key: NobleKey<V, 'local'>,
    plaintext: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: ImplicitAssertionParameters<V>
  ): Promise<Uint8Array> {
    return encryptPasetoLocalPayload(
      this.version,
      getKey(key, this.version, 'local', 'key').material,
      plaintext,
      generatedBytes(this.#randomBytes, this.version === 2 ? 24 : 32),
      footer,
      (implicitAssertion as readonly Uint8Array[])[0],
    )
  }

  async Decrypt(
    key: NobleKey<V, 'local'>,
    payload: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: ImplicitAssertionParameters<V>
  ): Promise<Uint8Array> {
    const material = getKey(key, this.version, 'local', 'key').material
    try {
      return decryptPasetoLocalPayload(
        this.version,
        material,
        payload,
        footer,
        (implicitAssertion as readonly Uint8Array[])[0],
      )
    } catch (cause) {
      throw new InvalidTokenError('Token authentication failed', { cause })
    }
  }
}

class NoblePublicProtocol<V extends ModernVersion> {
  readonly type = 'PUBLIC' as const
  readonly version: V
  readonly PASERK: Readonly<NoblePublicPASERK<V>>
  readonly #randomBytes: (length: number) => Uint8Array

  constructor(version: V, options: Readonly<NobleSuiteOptions>) {
    this.version = version
    this.#randomBytes = options.randomBytes ?? nobleRandomBytes
    const argon2id = validateArgon2id(options.argon2id ?? KDF_ARGON2ID)
    this.PASERK = Object.freeze(new NoblePublicPASERK(version, this.#randomBytes, argon2id))
  }

  async GenerateKeyPair(
    extractable: boolean,
  ): Promise<KeyPair<NobleKey<V, 'public'>, NobleKey<V, 'secret'>>> {
    const seed = generatedBytes(this.#randomBytes, 32)
    const publicMaterial = ed25519.getPublicKey(seed)
    return {
      publicKey: newKey(this.version, 'public', publicMaterial, true),
      secretKey: newKey(
        this.version,
        'secret',
        concat(seed, publicMaterial),
        extractable,
        publicMaterial,
      ),
    }
  }

  async Sign(
    key: NobleKey<V, 'secret'>,
    message: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: ImplicitAssertionParameters<V>
  ): Promise<Uint8Array> {
    const material = getKey(key, this.version, 'secret', 'key').material
    const pieces =
      this.version === 2
        ? [bytes('v2.public.'), message, footer]
        : [bytes('v4.public.'), message, footer, (implicitAssertion as readonly Uint8Array[])[0]!]
    return ed25519.sign(pae(pieces), material.subarray(0, 32))
  }

  async Verify(
    key: NobleKey<V, 'public'>,
    message: Uint8Array,
    signature: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: ImplicitAssertionParameters<V>
  ): Promise<boolean> {
    if (signature.byteLength !== 64) return false
    const material = getKey(key, this.version, 'public', 'key').material
    const pieces =
      this.version === 2
        ? [bytes('v2.public.'), message, footer]
        : [bytes('v4.public.'), message, footer, (implicitAssertion as readonly Uint8Array[])[0]!]
    try {
      return ed25519.verify(signature, pae(pieces), material, { zip215: false })
    } catch {
      return false
    }
  }
}

/** Atomic Noble capability factories for a complete v2/v4 `local` protocol. */
export interface NobleLocalCapabilities<V extends ModernVersion> {
  readonly GenerateKey: ReturnType<typeof LocalGenerateKey<V, NobleKey<V, 'local'>>>
  readonly Encrypt: ReturnType<typeof LocalEncrypt<V, NobleKey<V, 'local'>>>
  readonly Decrypt: ReturnType<typeof LocalDecrypt<V, NobleKey<V, 'local'>>>
  readonly ImportKey: ReturnType<typeof LocalImportKey<V, NobleKey<V, 'local'>>>
  readonly ExportKey: ReturnType<typeof LocalExportKey<V, NobleKey<V, 'local'>>>
  readonly KeyID: ReturnType<typeof LocalKeyID<V>>
  readonly GenerateWrappingKey: ReturnType<
    typeof LocalGenerateWrappingKey<V, NobleKey<V, 'wrapping'>>
  >
  readonly ImportWrappingKey: ReturnType<typeof LocalImportWrappingKey<V, NobleKey<V, 'wrapping'>>>
  readonly ExportWrappingKey: ReturnType<typeof LocalExportWrappingKey<V, NobleKey<V, 'wrapping'>>>
  readonly WrapKey: ReturnType<
    typeof LocalWrapKey<V, NobleKey<V, 'local'>, NobleKey<V, 'wrapping'>, 'pie'>
  >
  readonly UnwrapKey: ReturnType<
    typeof LocalUnwrapKey<V, NobleKey<V, 'local'>, NobleKey<V, 'wrapping'>, 'pie'>
  >
  readonly WrapKeyWithPassword: ReturnType<typeof LocalWrapKeyWithPassword<V, NobleKey<V, 'local'>>>
  readonly UnwrapKeyWithPassword: ReturnType<
    typeof LocalUnwrapKeyWithPassword<V, NobleKey<V, 'local'>>
  >
  readonly GenerateSealingKeyPair: ReturnType<
    typeof LocalGenerateSealingKeyPair<
      V,
      NobleKey<V, 'sealing-public'>,
      NobleKey<V, 'sealing-secret'>
    >
  >
  readonly ImportSealingPublicKey: ReturnType<
    typeof LocalImportSealingPublicKey<V, NobleKey<V, 'sealing-public'>>
  >
  readonly ImportSealingSecretKey: ReturnType<
    typeof LocalImportSealingSecretKey<V, NobleKey<V, 'sealing-secret'>>
  >
  readonly ExportSealingPublicKey: ReturnType<
    typeof LocalExportSealingPublicKey<V, NobleKey<V, 'sealing-public'>>
  >
  readonly ExportSealingSecretKey: ReturnType<
    typeof LocalExportSealingSecretKey<V, NobleKey<V, 'sealing-secret'>>
  >
  readonly SealKey: ReturnType<
    typeof LocalSealKey<V, NobleKey<V, 'local'>, NobleKey<V, 'sealing-public'>>
  >
  readonly UnsealKey: ReturnType<
    typeof LocalUnsealKey<V, NobleKey<V, 'local'>, NobleKey<V, 'sealing-secret'>>
  >
}

/** Atomic Noble capability factories for a complete v2/v4 `public` protocol. */
export interface NoblePublicCapabilities<V extends ModernVersion> {
  readonly GenerateKeyPair: ReturnType<
    typeof PublicGenerateKeyPair<V, NobleKey<V, 'public'>, NobleKey<V, 'secret'>>
  >
  readonly Sign: ReturnType<typeof PublicSign<V, NobleKey<V, 'secret'>>>
  readonly Verify: ReturnType<typeof PublicVerify<V, NobleKey<V, 'public'>>>
  readonly ImportPublicKey: ReturnType<typeof PublicImportPublicKey<V, NobleKey<V, 'public'>>>
  readonly ExportPublicKey: ReturnType<typeof PublicExportPublicKey<V, NobleKey<V, 'public'>>>
  readonly ImportSecretKey: ReturnType<typeof PublicImportSecretKey<V, NobleKey<V, 'secret'>>>
  readonly ExportSecretKey: ReturnType<typeof PublicExportSecretKey<V, NobleKey<V, 'secret'>>>
  readonly GetPublicKey: ReturnType<
    typeof PublicGetPublicKey<V, NobleKey<V, 'public'>, NobleKey<V, 'secret'>>
  >
  readonly PublicKeyID: ReturnType<typeof PublicKeyID<V>>
  readonly SecretKeyID: ReturnType<typeof SecretKeyID<V>>
  readonly GenerateWrappingKey: ReturnType<
    typeof PublicGenerateWrappingKey<V, NobleKey<V, 'wrapping'>>
  >
  readonly ImportWrappingKey: ReturnType<typeof PublicImportWrappingKey<V, NobleKey<V, 'wrapping'>>>
  readonly ExportWrappingKey: ReturnType<typeof PublicExportWrappingKey<V, NobleKey<V, 'wrapping'>>>
  readonly WrapSecretKey: ReturnType<
    typeof PublicWrapSecretKey<V, NobleKey<V, 'secret'>, NobleKey<V, 'wrapping'>, 'pie'>
  >
  readonly UnwrapSecretKey: ReturnType<
    typeof PublicUnwrapSecretKey<V, NobleKey<V, 'secret'>, NobleKey<V, 'wrapping'>, 'pie'>
  >
  readonly WrapSecretKeyWithPassword: ReturnType<
    typeof PublicWrapSecretKeyWithPassword<V, NobleKey<V, 'secret'>>
  >
  readonly UnwrapSecretKeyWithPassword: ReturnType<
    typeof PublicUnwrapSecretKeyWithPassword<V, NobleKey<V, 'secret'>>
  >
}

/** Create a flat map of private Noble v2/v4 `local` capability factories. */
export function createLocalCapabilities<V extends ModernVersion>(
  version: V,
  options: Readonly<NobleSuiteOptions> = {},
): Readonly<NobleLocalCapabilities<V>> {
  if (version !== 2 && version !== 4) throw new TypeError('Expected PASETO version 2 or 4')
  const implementation = new NobleLocalProtocol(version, options)
  const paserk = implementation.PASERK
  return Object.freeze({
    GenerateKey: LocalGenerateKey<V, NobleKey<V, 'local'>>({
      version,
      run: implementation.GenerateKey.bind(implementation),
    }),
    Encrypt: LocalEncrypt<V, NobleKey<V, 'local'>>({
      version,
      run: implementation.Encrypt.bind(implementation),
    }),
    Decrypt: LocalDecrypt<V, NobleKey<V, 'local'>>({
      version,
      run: implementation.Decrypt.bind(implementation),
    }),
    ImportKey: LocalImportKey<V, NobleKey<V, 'local'>>({
      version,
      run: async (value, extractable) => await paserk.Deserialize(value, { extractable }),
    }),
    ExportKey: LocalExportKey<V, NobleKey<V, 'local'>>({
      version,
      run: paserk.Serialize.bind(paserk),
    }),
    KeyID: LocalKeyID<V>({ version, run: paserk.ID.bind(paserk) }),
    GenerateWrappingKey: LocalGenerateWrappingKey<V, NobleKey<V, 'wrapping'>>({
      version,
      run: async (extractable) => await paserk.GenerateWrappingKey({ extractable }),
    }),
    ImportWrappingKey: LocalImportWrappingKey<V, NobleKey<V, 'wrapping'>>({
      version,
      run: async (material, extractable) =>
        await paserk.ImportWrappingKey(material, { extractable }),
    }),
    ExportWrappingKey: LocalExportWrappingKey<V, NobleKey<V, 'wrapping'>>({
      version,
      run: paserk.ExportWrappingKey.bind(paserk),
    }),
    WrapKey: LocalWrapKey<V, NobleKey<V, 'local'>, NobleKey<V, 'wrapping'>, 'pie'>({
      version,
      run: paserk.Wrap.bind(paserk),
    }),
    UnwrapKey: LocalUnwrapKey<V, NobleKey<V, 'local'>, NobleKey<V, 'wrapping'>, 'pie'>({
      version,
      run: async (value, wrappingKey, extractable) =>
        await paserk.Unwrap(value, wrappingKey, { extractable }),
    }),
    WrapKeyWithPassword: LocalWrapKeyWithPassword<V, NobleKey<V, 'local'>>({
      version,
      run: paserk.WrapWithPassword.bind(paserk),
    }),
    UnwrapKeyWithPassword: LocalUnwrapKeyWithPassword<V, NobleKey<V, 'local'>>({
      version,
      run: async (value, password, limits, extractable) =>
        await paserk.UnwrapWithPassword(value, password, limits as PasswordUnwrapLimits, {
          extractable,
        }),
    }),
    GenerateSealingKeyPair: LocalGenerateSealingKeyPair<
      V,
      NobleKey<V, 'sealing-public'>,
      NobleKey<V, 'sealing-secret'>
    >({
      version,
      run: async (extractable) => await paserk.GenerateSealingKeyPair({ extractable }),
    }),
    ImportSealingPublicKey: LocalImportSealingPublicKey<V, NobleKey<V, 'sealing-public'>>({
      version,
      run: paserk.ImportSealingPublicKey.bind(paserk),
    }),
    ImportSealingSecretKey: LocalImportSealingSecretKey<V, NobleKey<V, 'sealing-secret'>>({
      version,
      run: async (material, extractable) =>
        await paserk.ImportSealingSecretKey(material, { extractable }),
    }),
    ExportSealingPublicKey: LocalExportSealingPublicKey<V, NobleKey<V, 'sealing-public'>>({
      version,
      run: paserk.ExportSealingPublicKey.bind(paserk),
    }),
    ExportSealingSecretKey: LocalExportSealingSecretKey<V, NobleKey<V, 'sealing-secret'>>({
      version,
      run: paserk.ExportSealingSecretKey.bind(paserk),
    }),
    SealKey: LocalSealKey<V, NobleKey<V, 'local'>, NobleKey<V, 'sealing-public'>>({
      version,
      run: paserk.Seal.bind(paserk),
    }),
    UnsealKey: LocalUnsealKey<V, NobleKey<V, 'local'>, NobleKey<V, 'sealing-secret'>>({
      version,
      run: async (value, recipient, extractable) =>
        await paserk.Unseal(value, recipient, { extractable }),
    }),
  })
}

/** Create a flat map of private Noble v2/v4 `public` capability factories. */
export function createPublicCapabilities<V extends ModernVersion>(
  version: V,
  options: Readonly<NobleSuiteOptions> = {},
): Readonly<NoblePublicCapabilities<V>> {
  if (version !== 2 && version !== 4) throw new TypeError('Expected PASETO version 2 or 4')
  const implementation = new NoblePublicProtocol(version, options)
  const paserk = implementation.PASERK
  return Object.freeze({
    GenerateKeyPair: PublicGenerateKeyPair<V, NobleKey<V, 'public'>, NobleKey<V, 'secret'>>({
      version,
      run: implementation.GenerateKeyPair.bind(implementation),
    }),
    Sign: PublicSign<V, NobleKey<V, 'secret'>>({
      version,
      run: implementation.Sign.bind(implementation),
    }),
    Verify: PublicVerify<V, NobleKey<V, 'public'>>({
      version,
      run: implementation.Verify.bind(implementation),
    }),
    ImportPublicKey: PublicImportPublicKey<V, NobleKey<V, 'public'>>({
      version,
      run: paserk.DeserializePublic.bind(paserk),
    }),
    ExportPublicKey: PublicExportPublicKey<V, NobleKey<V, 'public'>>({
      version,
      run: paserk.SerializePublic.bind(paserk),
    }),
    ImportSecretKey: PublicImportSecretKey<V, NobleKey<V, 'secret'>>({
      version,
      run: async (value, extractable) => await paserk.DeserializeSecret(value, { extractable }),
    }),
    ExportSecretKey: PublicExportSecretKey<V, NobleKey<V, 'secret'>>({
      version,
      run: paserk.SerializeSecret.bind(paserk),
    }),
    GetPublicKey: PublicGetPublicKey<V, NobleKey<V, 'public'>, NobleKey<V, 'secret'>>({
      version,
      run: paserk.GetPublicKey.bind(paserk),
    }),
    PublicKeyID: PublicKeyID<V>({ version, run: paserk.PublicID.bind(paserk) }),
    SecretKeyID: SecretKeyID<V>({ version, run: paserk.SecretID.bind(paserk) }),
    GenerateWrappingKey: PublicGenerateWrappingKey<V, NobleKey<V, 'wrapping'>>({
      version,
      run: async (extractable) => await paserk.GenerateWrappingKey({ extractable }),
    }),
    ImportWrappingKey: PublicImportWrappingKey<V, NobleKey<V, 'wrapping'>>({
      version,
      run: async (material, extractable) =>
        await paserk.ImportWrappingKey(material, { extractable }),
    }),
    ExportWrappingKey: PublicExportWrappingKey<V, NobleKey<V, 'wrapping'>>({
      version,
      run: paserk.ExportWrappingKey.bind(paserk),
    }),
    WrapSecretKey: PublicWrapSecretKey<V, NobleKey<V, 'secret'>, NobleKey<V, 'wrapping'>, 'pie'>({
      version,
      run: paserk.WrapSecret.bind(paserk),
    }),
    UnwrapSecretKey: PublicUnwrapSecretKey<
      V,
      NobleKey<V, 'secret'>,
      NobleKey<V, 'wrapping'>,
      'pie'
    >({
      version,
      run: async (value, wrappingKey, extractable) =>
        await paserk.UnwrapSecret(value, wrappingKey, { extractable }),
    }),
    WrapSecretKeyWithPassword: PublicWrapSecretKeyWithPassword<V, NobleKey<V, 'secret'>>({
      version,
      run: paserk.WrapSecretWithPassword.bind(paserk),
    }),
    UnwrapSecretKeyWithPassword: PublicUnwrapSecretKeyWithPassword<V, NobleKey<V, 'secret'>>({
      version,
      run: async (value, password, limits, extractable) =>
        await paserk.UnwrapSecretWithPassword(value, password, limits as PasswordUnwrapLimits, {
          extractable,
        }),
    }),
  })
}

/** Complete private Noble PASETO v2.local and PASERK k2 capability map. */
export const V2_LOCAL: Readonly<NobleLocalCapabilities<2>> = createLocalCapabilities(2)

/** Complete private Noble PASETO v2.public and PASERK k2 capability map. */
export const V2_PUBLIC: Readonly<NoblePublicCapabilities<2>> = createPublicCapabilities(2)

/** Complete private Noble PASETO v4.local and PASERK k4 capability map. */
export const V4_LOCAL: Readonly<NobleLocalCapabilities<4>> = createLocalCapabilities(4)

/** Complete private Noble PASETO v4.public and PASERK k4 capability map. */
export const V4_PUBLIC: Readonly<NoblePublicCapabilities<4>> = createPublicCapabilities(4)
