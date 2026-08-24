import { InvalidKeyError, type CryptoKey, type Key, type Version } from '../index.ts'

import { copyBytes } from './bytes.ts'

export interface LocalKey<V extends Version = Version> extends Key {
  readonly algorithm: { readonly name: `PASETO v${V}.local` }
  readonly type: 'secret'
  readonly version: V
  readonly kind: 'local'
}

export interface PublicKey<V extends Version = Version> extends Key {
  readonly algorithm: { readonly name: `PASETO v${V}.public` }
  readonly type: 'public'
  readonly version: V
  readonly kind: 'public'
}

export interface SecretKey<V extends Version = Version> extends Key {
  readonly algorithm: { readonly name: `PASETO v${V}.public` }
  readonly type: 'secret'
  readonly version: V
  readonly kind: 'secret'
}

export interface WrappingKey<V extends Version = Version> extends Key {
  readonly algorithm: { readonly name: `PASERK k${V}.wrap` }
  readonly type: 'secret'
  readonly version: V
  readonly kind: 'wrapping'
}

export interface SealingPublicKey<V extends Version = Version> extends Key {
  readonly algorithm: { readonly name: `PASERK k${V}.seal` }
  readonly extractable: true
  readonly type: 'public'
  readonly version: V
  readonly kind: 'sealing-public'
}

export interface SealingSecretKey<V extends Version = Version> extends Key {
  readonly algorithm: { readonly name: `PASERK k${V}.seal` }
  readonly type: 'secret'
  readonly version: V
  readonly kind: 'sealing-secret'
}

export interface KeyData<V extends Version> {
  version: V
  material: Uint8Array
  extractable: boolean
}

export interface LocalKeyData<V extends Version> {
  version: V
  material: Uint8Array | undefined
  cryptoKey: CryptoKey | undefined
  extractable: boolean
}

export interface PublicKeyData<V extends Version> {
  version: V
  material: Uint8Array | undefined
  cryptoKey: CryptoKey
  extractable: boolean
}

export interface SecretKeyData<V extends Version> {
  version: V
  material: Uint8Array | undefined
  cryptoKey: CryptoKey
  publicCryptoKey: CryptoKey
  publicMaterial: Uint8Array | undefined
  rawPublicMaterial?: Uint8Array | undefined
  extractable: boolean
}

export interface SealingSecretKeyData<V extends Version> extends KeyData<V> {
  publicMaterial: Uint8Array
}

const localKeys = /* @__PURE__ */ new WeakMap<object, LocalKeyData<Version>>()
const publicKeys = /* @__PURE__ */ new WeakMap<object, PublicKeyData<Version>>()
const secretKeys = /* @__PURE__ */ new WeakMap<object, SecretKeyData<Version>>()
const wrappingKeys = /* @__PURE__ */ new WeakMap<object, KeyData<Version>>()
const sealingPublicKeys = /* @__PURE__ */ new WeakMap<object, KeyData<Version>>()
const sealingSecretKeys = /* @__PURE__ */ new WeakMap<object, SealingSecretKeyData<Version>>()

export class LocalKeyImpl<V extends Version> implements LocalKey<V> {
  readonly #brand: undefined
  readonly algorithm: { readonly name: `PASETO v${V}.local` }
  readonly type = 'secret' as const
  readonly kind = 'local' as const
  readonly version: V
  readonly extractable: boolean

  constructor(
    version: V,
    material: Uint8Array | undefined,
    extractable: boolean,
    cryptoKey?: CryptoKey,
  ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASETO v${version}.local` }
    this.version = version
    this.extractable = extractable
    localKeys.set(this, {
      version,
      material: material === undefined ? undefined : copyBytes(material),
      cryptoKey,
      extractable,
    })
  }
}

export class PublicKeyImpl<V extends Version> implements PublicKey<V> {
  readonly #brand: undefined
  readonly algorithm: { readonly name: `PASETO v${V}.public` }
  readonly type = 'public' as const
  readonly kind = 'public' as const
  readonly version: V
  readonly extractable: boolean

  constructor(version: V, material: Uint8Array | undefined, cryptoKey: CryptoKey) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASETO v${version}.public` }
    this.version = version
    this.extractable = cryptoKey.extractable
    publicKeys.set(this, {
      version,
      material: material === undefined ? undefined : copyBytes(material),
      cryptoKey,
      extractable: this.extractable,
    })
  }
}

export class SecretKeyImpl<V extends Version> implements SecretKey<V> {
  readonly #brand: undefined
  readonly algorithm: { readonly name: `PASETO v${V}.public` }
  readonly type = 'secret' as const
  readonly kind = 'secret' as const
  readonly version: V
  readonly extractable: boolean

  constructor(
    version: V,
    cryptoKey: CryptoKey,
    material: Uint8Array | undefined,
    publicMaterial: Uint8Array,
    rawPublicMaterial: Uint8Array | undefined,
    publicCryptoKey: CryptoKey,
  ) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASETO v${version}.public` }
    this.version = version
    this.extractable = cryptoKey.extractable
    secretKeys.set(this, {
      version,
      material: material === undefined ? undefined : copyBytes(material),
      cryptoKey,
      publicCryptoKey,
      publicMaterial: publicMaterial === undefined ? undefined : copyBytes(publicMaterial),
      rawPublicMaterial: rawPublicMaterial === undefined ? undefined : copyBytes(rawPublicMaterial),
      extractable: cryptoKey.extractable,
    })
  }
}

export class WrappingKeyImpl<V extends Version> implements WrappingKey<V> {
  readonly #brand: undefined
  readonly algorithm: { readonly name: `PASERK k${V}.wrap` }
  readonly type = 'secret' as const
  readonly kind = 'wrapping' as const
  readonly version: V
  readonly extractable: boolean

  constructor(version: V, material: Uint8Array, extractable: boolean) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASERK k${version}.wrap` }
    this.version = version
    this.extractable = extractable
    wrappingKeys.set(this, { version, material: copyBytes(material), extractable })
  }
}

export class SealingPublicKeyImpl<V extends Version> implements SealingPublicKey<V> {
  readonly #brand: undefined
  readonly algorithm: { readonly name: `PASERK k${V}.seal` }
  readonly type = 'public' as const
  readonly kind = 'sealing-public' as const
  readonly version: V
  readonly extractable = true

  constructor(version: V, material: Uint8Array) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASERK k${version}.seal` }
    this.version = version
    sealingPublicKeys.set(this, { version, material: copyBytes(material), extractable: true })
  }
}

export class SealingSecretKeyImpl<V extends Version> implements SealingSecretKey<V> {
  readonly #brand: undefined
  readonly algorithm: { readonly name: `PASERK k${V}.seal` }
  readonly type = 'secret' as const
  readonly kind = 'sealing-secret' as const
  readonly version: V
  readonly extractable: boolean

  constructor(version: V, material: Uint8Array, publicMaterial: Uint8Array, extractable: boolean) {
    this.#brand = undefined
    void this.#brand
    this.algorithm = { name: `PASERK k${version}.seal` }
    this.version = version
    this.extractable = extractable
    sealingSecretKeys.set(this, {
      version,
      material: copyBytes(material),
      publicMaterial: copyBytes(publicMaterial),
      extractable,
    })
  }
}

function keyData<V extends Version>(
  map: WeakMap<object, KeyData<Version>>,
  key: object,
  version: V,
  name: string,
): KeyData<V> {
  const data = map.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"${name}" is not a v${version} key for this operation`)
  }
  return data as KeyData<V>
}

export function localKeyData<V extends Version>(
  key: object,
  version: V,
  name: string = 'key',
): LocalKeyData<V> {
  const data = localKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"${name}" is not a v${version} key for this operation`)
  }
  return data as LocalKeyData<V>
}

export function publicKeyData<V extends Version>(
  key: object,
  version: V,
  name: string = 'key',
): PublicKeyData<V> {
  const data = publicKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"${name}" is not a v${version} key for this operation`)
  }
  return data as PublicKeyData<V>
}

export function secretKeyData<V extends Version>(key: object, version: V): SecretKeyData<V> {
  const data = secretKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"key" is not a v${version} secret key`)
  }
  return data as SecretKeyData<V>
}

export function wrappingKeyData<V extends Version>(
  key: object,
  version: V,
  name: string = 'key',
): KeyData<V> {
  return keyData(wrappingKeys, key, version, name)
}

export function sealingPublicKeyData<V extends Version>(
  key: object,
  version: V,
  name: string = 'key',
): KeyData<V> {
  return keyData(sealingPublicKeys, key, version, name)
}

export function sealingSecretKeyData<V extends Version>(
  key: object,
  version: V,
): SealingSecretKeyData<V> {
  const data = sealingSecretKeys.get(key)
  if (!data || data.version !== version) {
    throw new InvalidKeyError(`"key" is not a k${version}.seal secret key`)
  }
  return data as SealingSecretKeyData<V>
}

export function requireExtractable(data: { readonly extractable: boolean }): void {
  if (!data.extractable) throw new InvalidKeyError('Key is not extractable')
}
