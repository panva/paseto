/**
 * Protocol-neutral PASETO and PASERK composition APIs for JavaScript runtimes.
 *
 * @module paseto
 * @category Protocol Composition
 * @categoryDescription Protocol Composition
 * Version and purpose metadata plus the factories and types used to compose selected capabilities.
 *
 * @categoryDescription Local Token Operations
 * Low-level contracts and creators for local-token encryption and decryption.
 *
 * @categoryDescription Local Key Management
 * Contracts and creators for generating, importing, exporting, and identifying local keys.
 *
 * @categoryDescription Local Key Wrapping
 * Contracts and creators for local wrapping-key management and symmetric key wrapping.
 *
 * @categoryDescription Public Token Operations
 * Low-level contracts and creators for public-token signing and verification.
 *
 * @categoryDescription Public Key Management
 * Contracts and creators for managing signing and verification keys and their identifiers.
 *
 * @categoryDescription Public Key Wrapping
 * Contracts and creators for wrapping-key management and symmetric secret-key wrapping.
 *
 * @categoryDescription Password-Based Key Wrapping
 * Argon2id contracts, options, and creators for password-protected local and secret keys.
 *
 * @categoryDescription Key Sealing
 * Contracts and creators for sealing-key management and asymmetric local-key protection.
 *
 * @categoryDescription Tokens and Claims
 * Claim values, token production and consumption options, and authenticated token results.
 *
 * @categoryDescription Keys
 * Portable key representations, key pairs, and secret-key extractability options.
 *
 * @categoryDescription PASERK Serializations
 * Typed PASERK serializations and the serialization inputs accepted by key identifiers.
 *
 * @categoryDescription Utilities
 * Protocol-independent helpers for pre-authentication encoding and footer inspection.
 *
 * @categoryDescription Errors
 * Stable error codes and error classes produced by the protocol APIs.
 */

// ============================================================================
// Public types
// ============================================================================

/**
 * Supported PASETO and PASERK protocol versions.
 *
 * @category Protocol Composition
 */
export type Version = 1 | 2 | 3 | 4

/**
 * A value accepted in a PASETO claims object.
 *
 * @category Tokens and Claims
 */
export type JsonValue =
  null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue }

/**
 * A decoded PASETO claims object.
 *
 * Registered claims are strings. `exp`, `iat`, and `nbf` use RFC 3339 date-time strings rather than
 * numeric dates. Additional string-keyed claims may contain any {@link JsonValue}.
 *
 * @category Tokens and Claims
 */
export type Claims = { [key: string]: JsonValue } & {
  /** Intended audience. */
  aud?: string
  /** Expiration time as an RFC 3339 date-time string. */
  exp?: string
  /** Issued-at time as an RFC 3339 date-time string. */
  iat?: string
  /** Issuer. */
  iss?: string
  /** Token identifier. */
  jti?: string
  /** Not-before time as an RFC 3339 date-time string. */
  nbf?: string
  /** Subject. */
  sub?: string
}

type JsonCompatible<T> = T extends null | boolean | number | string
  ? T
  : T extends (...args: never[]) => unknown
    ? never
    : T extends readonly unknown[]
      ? { readonly [K in keyof T]: JsonCompatible<T[K]> }
      : T extends object
        ? { readonly [K in keyof T]: K extends string | number ? JsonCompatible<T[K]> : never }
        : never

type CompatibleClaims<T extends object> = T extends readonly unknown[]
  ? never
  : {
      readonly [K in keyof T]: K extends 'aud' | 'exp' | 'iat' | 'iss' | 'jti' | 'nbf' | 'sub'
        ? T[K] extends string | undefined
          ? T[K]
          : never
        : K extends string | number
          ? JsonCompatible<T[K]>
          : never
    }

/**
 * An application claims object accepted for token production.
 *
 * @typeParam T - Application claims type checked for JSON-compatible values and registered claims
 */
type ClaimsInput<T extends object> = T extends Claims ? T : T & CompatibleClaims<NoInfer<T>>

/**
 * Options controlling secret-key extractability.
 *
 * @category Keys
 */
export interface KeyOptions {
  /** Whether secret key material may later be exported or protected with PASERK. Defaults to false. */
  extractable?: boolean
}

/**
 * Options used when creating a token. All versions support `footer`, `now`, `addIssuedAt`,
 * `expiresIn`, and `nonExpiring`; only v3 and v4 support `implicitAssertion`.
 *
 * `expiresIn` and `nonExpiring: true` are mutually exclusive.
 *
 * @remarks
 * `expiresIn` is a lifetime in seconds, overrides an existing `exp` claim, and defaults to 3,600
 * when `exp` is absent. `nonExpiring: true` removes `exp` instead. In v3 and v4,
 * `implicitAssertion` is a `Uint8Array` that authenticates data not stored in the token.
 * @category Tokens and Claims
 * @typeParam V - PASETO version selecting whether implicit assertions are available
 */
export type ProduceOptions<V extends Version> = {
  /** Authenticated, unencrypted token footer. */
  footer?: Uint8Array
  /** Current time used for generated temporal claims. */
  now?: Date
  /** Add an `iat` claim when one is not already present. Defaults to true. */
  addIssuedAt?: boolean
  /** Lifetime in seconds. Overrides an `exp` claim. Defaults to 3600 when `exp` is absent. */
  expiresIn?: number
  /** Remove any `exp` claim when true; preserve normal expiration handling when false. */
  nonExpiring?: boolean
} & ([V] extends [3 | 4]
  ? {
      /** Authenticated data that is not stored in the token. */
      implicitAssertion?: Uint8Array
    }
  : {
      /** @internal */
      implicitAssertion?: never
    })

/**
 * Options used when consuming a token. All versions support `footer`, `now`, `clockTolerance`,
 * `allowNonExpiring`, `maxTokenAge`, `audience`, `issuer`, `subject`, `tokenIdentifier`, and
 * `requiredClaims`; only v3 and v4 support `implicitAssertion`.
 *
 * @remarks
 * In v3 and v4, `implicitAssertion` is a `Uint8Array` that authenticates data not stored in the
 * token. V1 and v2 do not accept it.
 * @category Tokens and Claims
 * @typeParam V - PASETO version selecting whether implicit assertions are available
 */
export type ConsumeOptions<V extends Version> = {
  /** Require the token to contain this exact footer. */
  footer?: Uint8Array
  /** Current time used for temporal claim validation. */
  now?: Date
  /** Permitted temporal skew in seconds. Defaults to zero. */
  clockTolerance?: number
  /** Accept a claims object without an `exp` claim. Defaults to false. */
  allowNonExpiring?: boolean
  /** Maximum token age in seconds, measured from `iat`. */
  maxTokenAge?: number
  /** Expected `aud` claim. Any listed value may match. */
  audience?: string | readonly string[]
  /** Expected `iss` claim. Any listed value may match. */
  issuer?: string | readonly string[]
  /** Expected `sub` claim. */
  subject?: string
  /** Expected `jti` claim. */
  tokenIdentifier?: string
  /** Additional claims that must be present. */
  requiredClaims?: readonly string[]
} & ([V] extends [3 | 4]
  ? {
      /** Authenticated data that is not stored in the token. */
      implicitAssertion?: Uint8Array
    }
  : {
      /** @internal */
      implicitAssertion?: never
    })

type ProduceOptionsRuntime = {
  footer?: Uint8Array
  now?: Date
  addIssuedAt?: boolean
  expiresIn?: number
  nonExpiring?: boolean
  implicitAssertion?: Uint8Array
}

type ConsumeOptionsRuntime = {
  footer?: Uint8Array
  now?: Date
  clockTolerance?: number
  allowNonExpiring?: boolean
  maxTokenAge?: number
  audience?: string | readonly string[]
  issuer?: string | readonly string[]
  subject?: string
  tokenIdentifier?: string
  requiredClaims?: readonly string[]
  implicitAssertion?: Uint8Array
}

/**
 * A successfully authenticated PASETO.
 *
 * `T` is for application wrappers that independently narrow `claims`. Capabilities created by
 * {@link LocalDecrypt} and {@link PublicVerify} return `TokenResult<Claims>`.
 *
 * @category Tokens and Claims
 * @typeParam T - Claims type supplied by an external narrowing wrapper
 */
export interface TokenResult<T extends object = Claims> {
  /** Authenticated claims. */
  claims: T
  /** Authenticated token footer. */
  footer: Uint8Array
}

/**
 * Parameters for an Argon2id implementation. Memory is expressed in bytes.
 *
 * @category Password-Based Key Wrapping
 */
export interface Argon2idParameters {
  /** Memory cost in bytes. */
  readonly memory: number
  /** Number of passes over memory. */
  readonly passes: number
  /** Degree of parallelism. */
  readonly parallelism: number
  /** Derived-key length in bytes. */
  readonly length: number
}

/**
 * Replaceable Argon2id implementation contract.
 *
 * @category Password-Based Key Wrapping
 */
export interface Argon2id {
  /** Type discriminator, always `KDF`. */
  readonly type: 'KDF'
  /** Argon2id implementation name. */
  readonly name: 'Argon2id' | (string & {})
  /**
   * Derives key material from a password using Argon2id.
   *
   * @param password - Password bytes
   * @param salt - Salt bytes
   * @param parameters - Argon2id parameters
   */
  Derive(
    password: Uint8Array,
    salt: Uint8Array,
    parameters: Readonly<Argon2idParameters>,
  ): Promise<Uint8Array>
}

/**
 * Factory function for an Argon2id implementation.
 *
 * @category Password-Based Key Wrapping
 */
export type Argon2idFactory = () => Readonly<Argon2id>

/**
 * Options used when unwrapping a password-protected PASERK. All versions support `extractable`; v1
 * and v3 support `maxIterations`, while v2 and v4 support `maxMemory`, `maxPasses`, and
 * `maxParallelism`.
 *
 * @remarks
 * `extractable` follows {@link KeyOptions}. All limit fields are numbers. For v1 and v3,
 * `maxIterations` defaults to 1,000,000. For v2 and v4, `maxMemory`, `maxPasses`, and
 * `maxParallelism` default to 1 GiB, 10, and 16, respectively.
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK version selecting PBKDF2 limits for v1/v3 or Argon2id limits for v2/v4
 */
export type PasswordUnwrapOptions<V extends Version> = KeyOptions &
  ([V] extends [1 | 3]
    ? {
        /** Maximum PBKDF2 iterations accepted. Defaults to 1,000,000. */
        maxIterations?: number
        /** @internal */
        maxMemory?: never
        /** @internal */
        maxPasses?: never
        /** @internal */
        maxParallelism?: never
      }
    : [V] extends [2 | 4]
      ? {
          /** @internal */
          maxIterations?: never
          /** Maximum Argon2 memory in bytes accepted. Defaults to 1 GiB. */
          maxMemory?: number
          /** Maximum Argon2 passes accepted. Defaults to 10. */
          maxPasses?: number
          /** Maximum Argon2 parallelism accepted. Defaults to 16. */
          maxParallelism?: number
        }
      : {
          /** @internal */
          maxIterations?: never
          /** @internal */
          maxMemory?: never
          /** @internal */
          maxPasses?: never
          /** @internal */
          maxParallelism?: never
        })

/**
 * Resource limits passed to a low-level password-unwrapping implementation. V1 and v3 receive
 * `maxIterations`; v2 and v4 receive `maxMemory`, `maxPasses`, and `maxParallelism`.
 *
 * The protocol adapter validates the caller's options and handles key extractability separately.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK version selecting PBKDF2 limits for v1/v3 or Argon2id limits for v2/v4
 */
export type PasswordUnwrapLimits<V extends Version> = [V] extends [1 | 3]
  ? { maxIterations?: number }
  : [V] extends [2 | 4]
    ? { maxMemory?: number; maxPasses?: number; maxParallelism?: number }
    : Record<PropertyKey, never>

/**
 * Minimal key representation understood by protocol implementations.
 *
 * It deliberately mirrors the structural-key convention used by `hpke`: implementations may return
 * Web Cryptography keys, HSM handles, native-addon keys, or their own opaque objects.
 *
 * @category Keys
 */
export interface Key {
  /** Algorithm metadata used by an implementation to identify its keys. */
  readonly algorithm: {
    /** Algorithm identifier for the key. */
    readonly name: string
  }
  /** Whether key material may be exported. */
  readonly extractable: boolean
  /** Implementation-defined key role. */
  readonly type: 'public' | 'secret' | (string & {})
}

/**
 * A Web Cryptography key as declared by the host runtime.
 *
 * This aliases the key type returned by the host's `SubtleCrypto.generateKey()` API when it is
 * exposed on `globalThis`. A structural fallback keeps the package portable to TypeScript projects
 * that do not include DOM or Node.js ambient types.
 *
 * @category Keys
 */
export type CryptoKey = typeof globalThis extends {
  crypto: { subtle: { generateKey(...args: any[]): Promise<infer R> } }
}
  ? Extract<R, { type: string }>
  : CryptoKeyStructuralFallback

/**
 * Used as {@link CryptoKey} when the host runtime's `crypto` global is not exposed on `typeof
 * globalThis`, including when it is absent from ambient types or declared with `const` or `let`. It
 * remains structurally compatible with host {@link !CryptoKey} declarations so values flow freely to
 * and from {@link !SubtleCrypto} APIs.
 *
 * @internal
 */
interface CryptoKeyStructuralFallback {
  readonly algorithm: { readonly name: string }
  readonly extractable: boolean
  readonly type: string
  readonly usages: string[]
}

/**
 * A public and secret key pair returned by a key-pair generation capability.
 *
 * @category Keys
 * @typeParam P - Public key representation contained in the pair
 * @typeParam S - Secret key representation contained in the pair
 */
export interface KeyPair<P extends Key, S extends Key> {
  /** Public key. */
  readonly publicKey: P
  /** Secret key. */
  readonly secretKey: S
}

/**
 * A plaintext symmetric-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type LocalPASERK<V extends Version = Version> = `k${V}.local.${string}`

/**
 * A plaintext public-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PublicPASERK<V extends Version = Version> = `k${V}.public.${string}`

/**
 * A plaintext secret-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SecretPASERK<V extends Version = Version> = `k${V}.secret.${string}`

/**
 * A local-key identifier PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type LocalIdPASERK<V extends Version = Version> = `k${V}.lid.${string}`

/**
 * A public-key identifier PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PublicIdPASERK<V extends Version = Version> = `k${V}.pid.${string}`

/**
 * A secret-key identifier PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SecretIdPASERK<V extends Version = Version> = `k${V}.sid.${string}`

/**
 * A symmetrically wrapped local-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type WrappedLocalPASERK<
  V extends Version = Version,
  Prefix extends string = string,
> = `k${V}.local-wrap.${Prefix}.${string}`

/**
 * A symmetrically wrapped secret-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type WrappedSecretPASERK<
  V extends Version = Version,
  Prefix extends string = string,
> = `k${V}.secret-wrap.${Prefix}.${string}`

/**
 * A password-wrapped local-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PasswordWrappedLocalPASERK<V extends Version = Version> = `k${V}.local-pw.${string}`

/**
 * A password-wrapped secret-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PasswordWrappedSecretPASERK<V extends Version = Version> = `k${V}.secret-pw.${string}`

/**
 * An asymmetrically sealed local-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SealedLocalPASERK<V extends Version = Version> = `k${V}.seal.${string}`

/**
 * Options used when password-wrapping a PASERK. V1 and v3 use PBKDF2 `iterations`; v2 and v4 use
 * Argon2id `memory`, `passes`, and `parallelism`.
 *
 * @remarks
 * All fields are numbers. For v1 and v3, `iterations` defaults to 100,000. For v2 and v4, `memory`,
 * `passes`, and `parallelism` default to 64 MiB, 2, and 1, respectively.
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK protocol version selecting the parameter set
 */
export type PasswordWrapOptions<V extends Version> = [V] extends [1 | 3]
  ? {
      /** PBKDF2 iteration count. Defaults to 100,000. */
      iterations?: number
      /** @internal */
      memory?: never
      /** @internal */
      passes?: never
      /** @internal */
      parallelism?: never
    }
  : [V] extends [2 | 4]
    ? {
        /** @internal */
        iterations?: never
        /** Argon2id memory limit in bytes. Defaults to 64 MiB. */
        memory?: number
        /** Number of Argon2id passes. Defaults to 2. */
        passes?: number
        /** Degree of Argon2id parallelism. Defaults to 1. */
        parallelism?: number
      }
    : Record<PropertyKey, never>

// ============================================================================
// Granular implementation capabilities
// ============================================================================

/**
 * Purpose discriminator carried by every capability.
 *
 * @category Protocol Composition
 */
export type Purpose = 'local' | 'public'

/**
 * Shared cross-copy recognition marker. Its globally registered key is intentionally reproducible;
 * this is an accidental-misuse check, not an authenticity or security boundary.
 */
const capabilityFactoryMarker = /* @__PURE__ */ Symbol.for('panva.paseto.capabilityFactory')

type OperationMethod = (...args: never[]) => unknown

/**
 * A low-level implementation with no protocol framing attached.
 *
 * @typeParam V - Protocol version implemented by the operation
 * @typeParam R - Low-level operation call signature
 * @inline
 */
interface OperationImplementation<V extends Version, R extends OperationMethod> {
  /** Protocol version implemented by the operation. */
  readonly version: V
  /** Low-level operation implementation. */
  readonly run: R
}

/**
 * A protocol-operation factory returned by a root operation creator and recognized by protocol
 * constructors. Its structural callable type permits composition across package copies; runtime
 * recognition is not a provenance guarantee.
 *
 * @category Protocol Composition
 * @typeParam P - Protocol purpose bound to the capability
 * @typeParam V - Protocol version bound to the capability
 * @typeParam O - Operation name bound to the capability
 * @typeParam R - Operation call signature
 */
export interface CapabilityFactory<
  P extends Purpose,
  V extends Version,
  O extends string,
  R extends (...args: never[]) => unknown,
> {
  /** Creates the validated, protocol-bound operation installed by a protocol constructor. */
  (): Readonly<{ readonly purpose: P; readonly version: V; readonly operation: O; readonly run: R }>
}
/**
 * A PASERK serialization accepted when deriving a local key identifier.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type LocalKeyIDInput<V extends Version = Version> =
  LocalPASERK<V> | WrappedLocalPASERK<V> | PasswordWrappedLocalPASERK<V> | SealedLocalPASERK<V>
type StrictOptions<Shape, Options extends Shape> = Options &
  Record<Exclude<keyof Options, keyof Shape>, never>
type LocalEncryptMethod<V extends Version, L extends Key> = <
  const C extends object,
  const Options extends ProduceOptions<V> = ProduceOptions<V>,
>(
  key: L,
  claims: ClaimsInput<C>,
  options?: StrictOptions<ProduceOptions<V>, Options>,
) => Promise<string>
type LocalDecryptMethod<V extends Version, L extends Key> = <
  const Options extends ConsumeOptions<V> = ConsumeOptions<V>,
>(
  key: L,
  token: string,
  options?: StrictOptions<ConsumeOptions<V>, Options>,
) => Promise<TokenResult>

/**
 * Low-level local key generation implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalGenerateKeyImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (extractable: boolean) => Promise<L>
}>
/**
 * Low-level local token encryption implementation.
 *
 * @remarks
 * In v1 and v2, `run` receives `key`, `input`, and `footer`. In v3 and v4, it also receives a
 * required final `implicitAssertion` argument as a `Uint8Array`.
 * @category Local Token Operations
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalEncryptImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (
    key: L,
    input: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: [V] extends [1 | 2]
      ? []
      : [V] extends [3 | 4]
        ? [implicitAssertion: Uint8Array]
        : [implicitAssertion?: Uint8Array]
  ) => Promise<Uint8Array>
}>
/**
 * Low-level local token decryption implementation.
 *
 * @remarks
 * In v1 and v2, `run` receives `key`, `input`, and `footer`. In v3 and v4, it also receives a
 * required final `implicitAssertion` argument as a `Uint8Array`.
 * @category Local Token Operations
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalDecryptImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (
    key: L,
    input: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: [V] extends [1 | 2]
      ? []
      : [V] extends [3 | 4]
        ? [implicitAssertion: Uint8Array]
        : [implicitAssertion?: Uint8Array]
  ) => Promise<Uint8Array>
}>
/**
 * Low-level local key import implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalImportKeyImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (paserk: `k${V}.local.${string}`, extractable: boolean) => Promise<L>
}>
/**
 * Low-level local key export implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalExportKeyImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (key: L) => Promise<`k${V}.local.${string}`>
}>
/**
 * Low-level local key identifier implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 */
export type LocalKeyIDImplementation<V extends Version> = Readonly<{
  readonly version: V
  readonly run: (paserk: LocalKeyIDInput<V>) => Promise<`k${V}.lid.${string}`>
}>
/**
 * Low-level wrapping key generation implementation for local-purpose keys.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type LocalGenerateWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
  readonly version: V
  readonly run: (extractable: boolean) => Promise<W>
}>
/**
 * Low-level wrapping key import implementation for local-purpose keys.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type LocalImportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
  readonly version: V
  readonly run: (material: Uint8Array, extractable: boolean) => Promise<W>
}>
/**
 * Low-level wrapping key export implementation for local-purpose keys.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type LocalExportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
  readonly version: V
  readonly run: (key: W) => Promise<Uint8Array>
}>
/**
 * Low-level local key wrapping implementation.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type LocalWrapKeyImplementation<
  V extends Version,
  L extends Key,
  W extends Key,
  Prefix extends string = string,
> = Readonly<{
  readonly version: V
  readonly run: (key: L, wrappingKey: W) => Promise<`k${V}.local-wrap.${Prefix}.${string}`>
}>
/**
 * Low-level local key unwrapping implementation.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type LocalUnwrapKeyImplementation<
  V extends Version,
  L extends Key,
  W extends Key,
  Prefix extends string = string,
> = Readonly<{
  readonly version: V
  readonly run: (
    paserk: `k${V}.local-wrap.${Prefix}.${string}`,
    wrappingKey: W,
    extractable: boolean,
  ) => Promise<L>
}>
/**
 * Low-level password-based local key wrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalWrapKeyWithPasswordImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (
    key: L,
    password: Uint8Array,
    options: PasswordWrapOptions<V>,
  ) => Promise<`k${V}.local-pw.${string}`>
}>
/**
 * Low-level password-based local key unwrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalUnwrapKeyWithPasswordImplementation<V extends Version, L extends Key> = Readonly<{
  readonly version: V
  readonly run: (
    paserk: `k${V}.local-pw.${string}`,
    password: Uint8Array,
    limits: PasswordUnwrapLimits<V>,
    extractable: boolean,
  ) => Promise<L>
}>
/**
 * Low-level sealing key pair generation implementation.
 *
 * `extractable` applies to the secret key. Sealing public keys are always extractable.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SP - Sealing public key representation
 * @typeParam SS - Sealing secret key representation
 */
export type LocalGenerateSealingKeyPairImplementation<
  V extends Version,
  SP extends Key,
  SS extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (extractable: boolean) => Promise<KeyPair<SP, SS>>
}>
/**
 * Low-level sealing public key import implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SP - Sealing public key representation
 */
export type LocalImportSealingPublicKeyImplementation<
  V extends Version,
  SP extends Key,
> = Readonly<{ readonly version: V; readonly run: (material: Uint8Array) => Promise<SP> }>
/**
 * Low-level sealing secret key import implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SS - Sealing secret key representation
 */
export type LocalImportSealingSecretKeyImplementation<
  V extends Version,
  SS extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (material: Uint8Array, extractable: boolean) => Promise<SS>
}>
/**
 * Low-level sealing public key export implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SP - Sealing public key representation
 */
export type LocalExportSealingPublicKeyImplementation<
  V extends Version,
  SP extends Key,
> = Readonly<{ readonly version: V; readonly run: (key: SP) => Promise<Uint8Array> }>
/**
 * Low-level sealing secret key export implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SS - Sealing secret key representation
 */
export type LocalExportSealingSecretKeyImplementation<
  V extends Version,
  SS extends Key,
> = Readonly<{ readonly version: V; readonly run: (key: SS) => Promise<Uint8Array> }>
/**
 * Low-level local key sealing implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam SP - Sealing public key representation
 */
export type LocalSealKeyImplementation<
  V extends Version,
  L extends Key,
  SP extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (key: L, recipient: SP) => Promise<`k${V}.seal.${string}`>
}>
/**
 * Low-level local key unsealing implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam SS - Sealing secret key representation
 */
export type LocalUnsealKeyImplementation<
  V extends Version,
  L extends Key,
  SS extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (paserk: `k${V}.seal.${string}`, recipient: SS, extractable: boolean) => Promise<L>
}>
/**
 * A PASERK serialization accepted when deriving a secret key identifier.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SecretKeyIDInput<V extends Version = Version> =
  SecretPASERK<V> | WrappedSecretPASERK<V> | PasswordWrappedSecretPASERK<V>
type PublicSignMethod<V extends Version, S extends Key> = <
  const C extends object,
  const Options extends ProduceOptions<V> = ProduceOptions<V>,
>(
  key: S,
  claims: ClaimsInput<C>,
  options?: StrictOptions<ProduceOptions<V>, Options>,
) => Promise<string>
type PublicVerifyMethod<V extends Version, P extends Key> = <
  const Options extends ConsumeOptions<V> = ConsumeOptions<V>,
>(
  key: P,
  token: string,
  options?: StrictOptions<ConsumeOptions<V>, Options>,
) => Promise<TokenResult>

/**
 * Low-level public-purpose key pair generation implementation.
 *
 * `extractable` applies to the secret signing key. Public verification keys are always extractable.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 * @typeParam S - Secret signing key representation
 */
export type PublicGenerateKeyPairImplementation<
  V extends Version,
  P extends Key,
  S extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (extractable: boolean) => Promise<KeyPair<P, S>>
}>
/**
 * Low-level public token signing implementation.
 *
 * @remarks
 * In v1 and v2, `run` receives `key`, `message`, and `footer`. In v3 and v4, it also receives a
 * required final `implicitAssertion` argument as a `Uint8Array`.
 * @category Public Token Operations
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicSignImplementation<V extends Version, S extends Key> = Readonly<{
  readonly version: V
  readonly run: (
    key: S,
    message: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: [V] extends [1 | 2]
      ? []
      : [V] extends [3 | 4]
        ? [implicitAssertion: Uint8Array]
        : [implicitAssertion?: Uint8Array]
  ) => Promise<Uint8Array>
}>
/**
 * Low-level public token verification implementation.
 *
 * @remarks
 * In v1 and v2, `run` receives `key`, `message`, `signature`, and `footer`. In v3 and v4, it also
 * receives a required final `implicitAssertion` argument as a `Uint8Array`.
 * @category Public Token Operations
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 */
export type PublicVerifyImplementation<V extends Version, P extends Key> = Readonly<{
  readonly version: V
  readonly run: (
    key: P,
    message: Uint8Array,
    signature: Uint8Array,
    footer: Uint8Array,
    ...implicitAssertion: [V] extends [1 | 2]
      ? []
      : [V] extends [3 | 4]
        ? [implicitAssertion: Uint8Array]
        : [implicitAssertion?: Uint8Array]
  ) => Promise<boolean>
}>
/**
 * Low-level public verification key import implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 */
export type PublicImportPublicKeyImplementation<V extends Version, P extends Key> = Readonly<{
  readonly version: V
  readonly run: (paserk: `k${V}.public.${string}`) => Promise<P>
}>
/**
 * Low-level public verification key export implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 */
export type PublicExportPublicKeyImplementation<V extends Version, P extends Key> = Readonly<{
  readonly version: V
  readonly run: (key: P) => Promise<`k${V}.public.${string}`>
}>
/**
 * Low-level secret signing key import implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicImportSecretKeyImplementation<V extends Version, S extends Key> = Readonly<{
  readonly version: V
  readonly run: (paserk: `k${V}.secret.${string}`, extractable: boolean) => Promise<S>
}>
/**
 * Low-level secret signing key export implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicExportSecretKeyImplementation<V extends Version, S extends Key> = Readonly<{
  readonly version: V
  readonly run: (key: S) => Promise<`k${V}.secret.${string}`>
}>
/**
 * Low-level public key derivation implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 * @typeParam S - Secret signing key representation
 */
export type PublicGetPublicKeyImplementation<
  V extends Version,
  P extends Key,
  S extends Key,
> = Readonly<{ readonly version: V; readonly run: (key: S) => Promise<P> }>
/**
 * Low-level public key identifier implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 */
export type PublicKeyIDImplementation<V extends Version> = Readonly<{
  readonly version: V
  readonly run: (paserk: `k${V}.public.${string}`) => Promise<`k${V}.pid.${string}`>
}>
/**
 * Low-level secret key identifier implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 */
export type SecretKeyIDImplementation<V extends Version> = Readonly<{
  readonly version: V
  readonly run: (paserk: SecretKeyIDInput<V>) => Promise<`k${V}.sid.${string}`>
}>
/**
 * Low-level wrapping key generation implementation for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type PublicGenerateWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
  readonly version: V
  readonly run: (extractable: boolean) => Promise<W>
}>
/**
 * Low-level wrapping key import implementation for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type PublicImportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
  readonly version: V
  readonly run: (material: Uint8Array, extractable: boolean) => Promise<W>
}>
/**
 * Low-level wrapping key export implementation for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type PublicExportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
  readonly version: V
  readonly run: (key: W) => Promise<Uint8Array>
}>
/**
 * Low-level secret key wrapping implementation.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type PublicWrapSecretKeyImplementation<
  V extends Version,
  S extends Key,
  W extends Key,
  Prefix extends string = string,
> = Readonly<{
  readonly version: V
  readonly run: (key: S, wrappingKey: W) => Promise<`k${V}.secret-wrap.${Prefix}.${string}`>
}>
/**
 * Low-level secret key unwrapping implementation.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type PublicUnwrapSecretKeyImplementation<
  V extends Version,
  S extends Key,
  W extends Key,
  Prefix extends string = string,
> = Readonly<{
  readonly version: V
  readonly run: (
    paserk: `k${V}.secret-wrap.${Prefix}.${string}`,
    wrappingKey: W,
    extractable: boolean,
  ) => Promise<S>
}>
/**
 * Low-level password-based secret key wrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicWrapSecretKeyWithPasswordImplementation<
  V extends Version,
  S extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (
    key: S,
    password: Uint8Array,
    options: PasswordWrapOptions<V>,
  ) => Promise<`k${V}.secret-pw.${string}`>
}>
/**
 * Low-level password-based secret key unwrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicUnwrapSecretKeyWithPasswordImplementation<
  V extends Version,
  S extends Key,
> = Readonly<{
  readonly version: V
  readonly run: (
    paserk: `k${V}.secret-pw.${string}`,
    password: Uint8Array,
    limits: PasswordUnwrapLimits<V>,
    extractable: boolean,
  ) => Promise<S>
}>

function validVersion(value: unknown): value is Version {
  return value === 1 || value === 2 || value === 3 || value === 4
}

function signatureLength(version: Version): number {
  switch (version) {
    case 1:
      return 256
    case 2:
    case 4:
      return 64
    case 3:
      return 96
  }
}

function createOperation<
  P extends Purpose,
  V extends Version,
  O extends string,
  I extends OperationMethod,
  R extends OperationMethod,
>(
  implementation: Readonly<OperationImplementation<V, I>>,
  purpose: P,
  operation: O,
  adapt: (implementation: Readonly<OperationImplementation<V, I>>) => R,
): CapabilityFactory<P, V, O, R> {
  const factory = function () {
    if (implementation === null || typeof implementation !== 'object') {
      throw new TypeError('implementation must be an object')
    }
    const version = implementation.version
    const sourceRun = implementation.run
    if (!validVersion(version)) {
      throw new TypeError('implementation has an invalid version')
    }
    if (typeof sourceRun !== 'function') {
      throw new TypeError('implementation has an invalid run function')
    }
    const snapshot: Readonly<OperationImplementation<V, I>> = Object.freeze({
      version,
      run: (async (...args: never[]) => {
        const changed = () => implementation.version !== version || implementation.run !== sourceRun
        if (changed()) {
          throw new TypeError('implementation version or run changed after composition')
        }
        const result = await Reflect.apply(
          sourceRun as unknown as CallableFunction,
          implementation,
          args,
        )
        if (changed()) {
          throw new TypeError('implementation version or run changed after composition')
        }
        return result
      }) as I,
    })
    const run = adapt(snapshot)
    if (typeof run !== 'function') {
      throw new TypeError('capability adapter returned an invalid run function')
    }
    return Object.freeze({ purpose, version: snapshot.version, operation, run })
  }
  Object.defineProperty(factory, capabilityFactoryMarker, { value: true })
  return factory as CapabilityFactory<P, V, O, R>
}

function implementationRun<V extends Version, R extends OperationMethod>(
  implementation: Readonly<OperationImplementation<V, R>>,
): R {
  return implementation.run
}

function runTokenImplementation<R>(
  version: Version,
  run: CallableFunction,
  parameters: unknown[],
  implicitAssertion: Uint8Array,
): Promise<R> {
  if (version >= 3) parameters.push(implicitAssertion)
  return Reflect.apply(run, undefined, parameters) as Promise<R>
}

/**
 * Creates a composable local key-generation capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local key-generation implementation
 */
export function LocalGenerateKey<V extends Version, L extends Key>(
  implementation: LocalGenerateKeyImplementation<V, L>,
): CapabilityFactory<'local', V, 'GenerateKey', (options?: KeyOptions) => Promise<L>> {
  return createOperation(
    implementation,
    'local',
    'GenerateKey',
    (value) => async (options?: KeyOptions) => await value.run(keyExtractable(options)),
  )
}

/**
 * Creates a composable local-token encryption capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `ProduceOptions<V>`.
 * @category Local Token Operations
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local-token encryption implementation
 */
export function LocalEncrypt<V extends Version, L extends Key>(
  implementation: LocalEncryptImplementation<V, L>,
): CapabilityFactory<
  'local',
  V,
  'Encrypt',
  <const C extends object, const Options extends ProduceOptions<V> = ProduceOptions<V>>(
    key: L,
    claims: ClaimsInput<C>,
    options?: Options & Record<Exclude<keyof Options, keyof ProduceOptions<V>>, never>,
  ) => Promise<string>
> {
  return createOperation(implementation, 'local', 'Encrypt', (value): LocalEncryptMethod<V, L> => {
    return async (key, claims, options) => {
      const resolved: ProduceOptions<V> = optionsObject(options)
      const footer = optionalBytes(resolved.footer, 'footer')
      const implicit = implicitAssertion(value.version, resolved)
      const payload = await runTokenImplementation(
        value.version,
        value.run,
        [key, prepareClaims(claims, resolved), footer],
        implicit,
      )
      checkBytes(payload, 'implementation Encrypt result')
      return formatToken(tokenHeader(value.version, 'local'), payload, footer)
    }
  })
}

/**
 * Creates a composable local-token decryption capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `ConsumeOptions<V>`.
 * @category Local Token Operations
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local-token decryption implementation
 */
export function LocalDecrypt<V extends Version, L extends Key>(
  implementation: LocalDecryptImplementation<V, L>,
): CapabilityFactory<
  'local',
  V,
  'Decrypt',
  <const Options extends ConsumeOptions<V> = ConsumeOptions<V>>(
    key: L,
    token: string,
    options?: Options & Record<Exclude<keyof Options, keyof ConsumeOptions<V>>, never>,
  ) => Promise<TokenResult>
> {
  return createOperation(implementation, 'local', 'Decrypt', (value): LocalDecryptMethod<V, L> => {
    return async (key, token, options) => {
      const resolved: ConsumeOptions<V> = optionsObject(options)
      const implicit = implicitAssertion(value.version, resolved)
      const { payload, footer } = parseToken(token, value.version, 'local', resolved)
      const plaintext = await runTokenImplementation(
        value.version,
        value.run,
        [key, payload, footer],
        implicit,
      )
      checkBytes(plaintext, 'implementation Decrypt result')
      const claims = parseClaims(plaintext)
      validateClaims(claims, resolved)
      return { claims, footer: copyBytes(footer) }
    }
  })
}

/**
 * Creates a composable local PASERK import capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local PASERK import implementation
 */
export function LocalImportKey<V extends Version, L extends Key>(
  implementation: LocalImportKeyImplementation<V, L>,
): CapabilityFactory<
  'local',
  V,
  'ImportKey',
  (paserk: `k${V}.local.${string}`, options?: KeyOptions) => Promise<L>
> {
  return createOperation(
    implementation,
    'local',
    'ImportKey',
    (value) => async (paserk, options) => await value.run(paserk, keyExtractable(options)),
  )
}

/**
 * Creates a composable local PASERK export capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local PASERK export implementation
 */
export function LocalExportKey<V extends Version, L extends Key>(
  implementation: LocalExportKeyImplementation<V, L>,
): CapabilityFactory<'local', V, 'ExportKey', (key: L) => Promise<`k${V}.local.${string}`>> {
  return createOperation(implementation, 'local', 'ExportKey', implementationRun)
}

/**
 * Creates a composable local PASERK ID capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @param implementation - Low-level local PASERK ID implementation
 */
export function LocalKeyID<V extends Version>(
  implementation: LocalKeyIDImplementation<V>,
): CapabilityFactory<
  'local',
  V,
  'KeyID',
  (paserk: LocalKeyIDInput<V>) => Promise<`k${V}.lid.${string}`>
> {
  return createOperation(implementation, 'local', 'KeyID', implementationRun)
}

/**
 * Creates a composable local wrapping-key generation capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key generation implementation
 */
export function LocalGenerateWrappingKey<V extends Version, W extends Key>(
  implementation: LocalGenerateWrappingKeyImplementation<V, W>,
): CapabilityFactory<'local', V, 'GenerateWrappingKey', (options?: KeyOptions) => Promise<W>> {
  return createOperation(
    implementation,
    'local',
    'GenerateWrappingKey',
    (value) => async (options?: KeyOptions) => await value.run(keyExtractable(options)),
  )
}

/**
 * Creates a composable local wrapping-key import capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key import implementation
 */
export function LocalImportWrappingKey<V extends Version, W extends Key>(
  implementation: LocalImportWrappingKeyImplementation<V, W>,
): CapabilityFactory<
  'local',
  V,
  'ImportWrappingKey',
  (material: Uint8Array, options?: KeyOptions) => Promise<W>
> {
  return createOperation(
    implementation,
    'local',
    'ImportWrappingKey',
    (value) => async (material, options) => await value.run(material, keyExtractable(options)),
  )
}

/**
 * Creates a composable local wrapping-key export capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key export implementation
 */
export function LocalExportWrappingKey<V extends Version, W extends Key>(
  implementation: LocalExportWrappingKeyImplementation<V, W>,
): CapabilityFactory<'local', V, 'ExportWrappingKey', (key: W) => Promise<Uint8Array>> {
  return createOperation(implementation, 'local', 'ExportWrappingKey', implementationRun)
}

/**
 * Creates a composable local key-wrapping capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 * @param implementation - Low-level local key-wrapping implementation
 */
export function LocalWrapKey<
  V extends Version,
  L extends Key,
  W extends Key,
  Prefix extends string = string,
>(
  implementation: LocalWrapKeyImplementation<V, L, W, Prefix>,
): CapabilityFactory<
  'local',
  V,
  'WrapKey',
  (key: L, wrappingKey: W) => Promise<`k${V}.local-wrap.${Prefix}.${string}`>
> {
  return createOperation(implementation, 'local', 'WrapKey', implementationRun)
}

/**
 * Creates a composable local key-unwrapping capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 * @param implementation - Low-level local key-unwrapping implementation
 */
export function LocalUnwrapKey<
  V extends Version,
  L extends Key,
  W extends Key,
  Prefix extends string = string,
>(
  implementation: LocalUnwrapKeyImplementation<V, L, W, Prefix>,
): CapabilityFactory<
  'local',
  V,
  'UnwrapKey',
  (
    paserk: `k${V}.local-wrap.${Prefix}.${string}`,
    wrappingKey: W,
    options?: KeyOptions,
  ) => Promise<L>
> {
  return createOperation(
    implementation,
    'local',
    'UnwrapKey',
    (value) => async (paserk, wrappingKey, options) =>
      await value.run(paserk, wrappingKey, keyExtractable(options)),
  )
}

/**
 * Creates a composable password-based local key-wrapping capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `PasswordWrapOptions<V>`.
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level password-based local key-wrapping implementation
 */
export function LocalWrapKeyWithPassword<V extends Version, L extends Key>(
  implementation: LocalWrapKeyWithPasswordImplementation<V, L>,
): CapabilityFactory<
  'local',
  V,
  'WrapKeyWithPassword',
  <const Options extends PasswordWrapOptions<V> = PasswordWrapOptions<V>>(
    key: L,
    password: Uint8Array,
    options?: Options & Record<Exclude<keyof Options, keyof PasswordWrapOptions<V>>, never>,
  ) => Promise<`k${V}.local-pw.${string}`>
> {
  return createOperation(
    implementation,
    'local',
    'WrapKeyWithPassword',
    (value) => async (key, password, options) => {
      const resolved: PasswordWrapOptions<V> = optionsObject(options)
      validatePasswordWrapOptions(value.version, resolved)
      return await value.run(key, password, resolved)
    },
  )
}

/**
 * Creates a composable password-based local key-unwrapping capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `PasswordUnwrapOptions<V>`.
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level password-based local key-unwrapping implementation
 */
export function LocalUnwrapKeyWithPassword<V extends Version, L extends Key>(
  implementation: LocalUnwrapKeyWithPasswordImplementation<V, L>,
): CapabilityFactory<
  'local',
  V,
  'UnwrapKeyWithPassword',
  <const Options extends PasswordUnwrapOptions<V> = PasswordUnwrapOptions<V>>(
    paserk: `k${V}.local-pw.${string}`,
    password: Uint8Array,
    options?: Options & Record<Exclude<keyof Options, keyof PasswordUnwrapOptions<V>>, never>,
  ) => Promise<L>
> {
  return createOperation(
    implementation,
    'local',
    'UnwrapKeyWithPassword',
    (value) => async (paserk, password, options) => {
      const resolved: PasswordUnwrapOptions<V> = optionsObject(options)
      validatePasswordUnwrapOptions(value.version, resolved)
      const extractable = booleanOption(resolved.extractable, 'extractable', false)
      const limits = { ...resolved }
      delete limits.extractable
      return await value.run(paserk, password, limits as PasswordUnwrapLimits<V>, extractable)
    },
  )
}

/**
 * Creates a composable sealing key-pair generation capability factory.
 *
 * The installed operation's `extractable` option applies to the secret key. The public key is
 * always extractable.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SP - Sealing public key representation
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level sealing key-pair generation implementation
 */
export function LocalGenerateSealingKeyPair<V extends Version, SP extends Key, SS extends Key>(
  implementation: LocalGenerateSealingKeyPairImplementation<V, SP, SS>,
): CapabilityFactory<
  'local',
  V,
  'GenerateSealingKeyPair',
  (options?: KeyOptions) => Promise<KeyPair<SP, SS>>
> {
  return createOperation(
    implementation,
    'local',
    'GenerateSealingKeyPair',
    (value) => async (options?: KeyOptions) => await value.run(keyExtractable(options)),
  )
}

/**
 * Creates a composable sealing public-key import capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SP - Sealing public key representation
 * @param implementation - Low-level sealing public-key import implementation
 */
export function LocalImportSealingPublicKey<V extends Version, SP extends Key>(
  implementation: LocalImportSealingPublicKeyImplementation<V, SP>,
): CapabilityFactory<'local', V, 'ImportSealingPublicKey', (material: Uint8Array) => Promise<SP>> {
  return createOperation(implementation, 'local', 'ImportSealingPublicKey', implementationRun)
}

/**
 * Creates a composable sealing secret-key import capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level sealing secret-key import implementation
 */
export function LocalImportSealingSecretKey<V extends Version, SS extends Key>(
  implementation: LocalImportSealingSecretKeyImplementation<V, SS>,
): CapabilityFactory<
  'local',
  V,
  'ImportSealingSecretKey',
  (material: Uint8Array, options?: KeyOptions) => Promise<SS>
> {
  return createOperation(
    implementation,
    'local',
    'ImportSealingSecretKey',
    (value) => async (material, options) => await value.run(material, keyExtractable(options)),
  )
}

/**
 * Creates a composable sealing public-key export capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SP - Sealing public key representation
 * @param implementation - Low-level sealing public-key export implementation
 */
export function LocalExportSealingPublicKey<V extends Version, SP extends Key>(
  implementation: LocalExportSealingPublicKeyImplementation<V, SP>,
): CapabilityFactory<'local', V, 'ExportSealingPublicKey', (key: SP) => Promise<Uint8Array>> {
  return createOperation(implementation, 'local', 'ExportSealingPublicKey', implementationRun)
}

/**
 * Creates a composable sealing secret-key export capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level sealing secret-key export implementation
 */
export function LocalExportSealingSecretKey<V extends Version, SS extends Key>(
  implementation: LocalExportSealingSecretKeyImplementation<V, SS>,
): CapabilityFactory<'local', V, 'ExportSealingSecretKey', (key: SS) => Promise<Uint8Array>> {
  return createOperation(implementation, 'local', 'ExportSealingSecretKey', implementationRun)
}

/**
 * Creates a composable local key-sealing capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @typeParam SP - Sealing public key representation
 * @param implementation - Low-level local key-sealing implementation
 */
export function LocalSealKey<V extends Version, L extends Key, SP extends Key>(
  implementation: LocalSealKeyImplementation<V, L, SP>,
): CapabilityFactory<
  'local',
  V,
  'SealKey',
  (key: L, recipient: SP) => Promise<`k${V}.seal.${string}`>
> {
  return createOperation(implementation, 'local', 'SealKey', implementationRun)
}

/**
 * Creates a composable local key-unsealing capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level local key-unsealing implementation
 */
export function LocalUnsealKey<V extends Version, L extends Key, SS extends Key>(
  implementation: LocalUnsealKeyImplementation<V, L, SS>,
): CapabilityFactory<
  'local',
  V,
  'UnsealKey',
  (paserk: `k${V}.seal.${string}`, recipient: SS, options?: KeyOptions) => Promise<L>
> {
  return createOperation(
    implementation,
    'local',
    'UnsealKey',
    (value) => async (paserk, recipient, options) =>
      await value.run(paserk, recipient, keyExtractable(options)),
  )
}

/**
 * Creates a composable public key-pair generation capability factory.
 *
 * The installed operation's `extractable` option applies to the secret signing key. The public
 * verification key is always extractable.
 *
 * @category Public Key Management
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level public key-pair generation implementation
 */
export function PublicGenerateKeyPair<V extends Version, P extends Key, S extends Key>(
  implementation: PublicGenerateKeyPairImplementation<V, P, S>,
): CapabilityFactory<
  'public',
  V,
  'GenerateKeyPair',
  (options?: KeyOptions) => Promise<KeyPair<P, S>>
> {
  return createOperation(
    implementation,
    'public',
    'GenerateKeyPair',
    (value) => async (options?: KeyOptions) => await value.run(keyExtractable(options)),
  )
}

/**
 * Creates a composable public-token signing capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `ProduceOptions<V>`.
 * @category Public Token Operations
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level public-token signing implementation
 */
export function PublicSign<V extends Version, S extends Key>(
  implementation: PublicSignImplementation<V, S>,
): CapabilityFactory<
  'public',
  V,
  'Sign',
  <const C extends object, const Options extends ProduceOptions<V> = ProduceOptions<V>>(
    key: S,
    claims: ClaimsInput<C>,
    options?: Options & Record<Exclude<keyof Options, keyof ProduceOptions<V>>, never>,
  ) => Promise<string>
> {
  return createOperation(implementation, 'public', 'Sign', (value): PublicSignMethod<V, S> => {
    return async (key, claims, options) => {
      const resolved: ProduceOptions<V> = optionsObject(options)
      const footer = optionalBytes(resolved.footer, 'footer')
      const implicit = implicitAssertion(value.version, resolved)
      const message = prepareClaims(claims, resolved)
      const signature = await runTokenImplementation(
        value.version,
        value.run,
        [key, message, footer],
        implicit,
      )
      checkBytes(signature, 'implementation Sign result', signatureLength(value.version))
      return formatToken(tokenHeader(value.version, 'public'), concat(message, signature), footer)
    }
  })
}

/**
 * Creates a composable public-token verification capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `ConsumeOptions<V>`.
 * @category Public Token Operations
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @param implementation - Low-level public-token verification implementation
 */
export function PublicVerify<V extends Version, P extends Key>(
  implementation: PublicVerifyImplementation<V, P>,
): CapabilityFactory<
  'public',
  V,
  'Verify',
  <const Options extends ConsumeOptions<V> = ConsumeOptions<V>>(
    key: P,
    token: string,
    options?: Options & Record<Exclude<keyof Options, keyof ConsumeOptions<V>>, never>,
  ) => Promise<TokenResult>
> {
  return createOperation(implementation, 'public', 'Verify', (value): PublicVerifyMethod<V, P> => {
    return async (key, token, options) => {
      const resolved: ConsumeOptions<V> = optionsObject(options)
      const implicit = implicitAssertion(value.version, resolved)
      const { payload, footer } = parseToken(token, value.version, 'public', resolved)
      const length = signatureLength(value.version)
      if (payload.byteLength <= length) {
        throw new InvalidTokenError('Truncated v' + value.version + '.public payload')
      }
      const message = payload.subarray(0, -length)
      const signature = payload.subarray(-length)
      if (
        (await runTokenImplementation(
          value.version,
          value.run,
          [key, message, signature, footer],
          implicit,
        )) !== true
      ) {
        throw new InvalidTokenError('Token signature verification failed')
      }
      const claims = parseClaims(message)
      validateClaims(claims, resolved)
      return { claims, footer: copyBytes(footer) }
    }
  })
}

/**
 * Creates a composable public PASERK import capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @param implementation - Low-level public PASERK import implementation
 */
export function PublicImportPublicKey<V extends Version, P extends Key>(
  implementation: PublicImportPublicKeyImplementation<V, P>,
): CapabilityFactory<
  'public',
  V,
  'ImportPublicKey',
  (paserk: `k${V}.public.${string}`) => Promise<P>
> {
  return createOperation(implementation, 'public', 'ImportPublicKey', implementationRun)
}

/**
 * Creates a composable public PASERK export capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @param implementation - Low-level public PASERK export implementation
 */
export function PublicExportPublicKey<V extends Version, P extends Key>(
  implementation: PublicExportPublicKeyImplementation<V, P>,
): CapabilityFactory<
  'public',
  V,
  'ExportPublicKey',
  (key: P) => Promise<`k${V}.public.${string}`>
> {
  return createOperation(implementation, 'public', 'ExportPublicKey', implementationRun)
}

/**
 * Creates a composable secret PASERK import capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level secret PASERK import implementation
 */
export function PublicImportSecretKey<V extends Version, S extends Key>(
  implementation: PublicImportSecretKeyImplementation<V, S>,
): CapabilityFactory<
  'public',
  V,
  'ImportSecretKey',
  (paserk: `k${V}.secret.${string}`, options?: KeyOptions) => Promise<S>
> {
  return createOperation(
    implementation,
    'public',
    'ImportSecretKey',
    (value) => async (paserk, options) => await value.run(paserk, keyExtractable(options)),
  )
}

/**
 * Creates a composable secret PASERK export capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level secret PASERK export implementation
 */
export function PublicExportSecretKey<V extends Version, S extends Key>(
  implementation: PublicExportSecretKeyImplementation<V, S>,
): CapabilityFactory<
  'public',
  V,
  'ExportSecretKey',
  (key: S) => Promise<`k${V}.secret.${string}`>
> {
  return createOperation(implementation, 'public', 'ExportSecretKey', implementationRun)
}

/**
 * Creates a composable public-key derivation capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level public-key derivation implementation
 */
export function PublicGetPublicKey<V extends Version, P extends Key, S extends Key>(
  implementation: PublicGetPublicKeyImplementation<V, P, S>,
): CapabilityFactory<'public', V, 'GetPublicKey', (key: S) => Promise<P>> {
  return createOperation(implementation, 'public', 'GetPublicKey', implementationRun)
}

/**
 * Creates a composable public PASERK ID capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @param implementation - Low-level public PASERK ID implementation
 */
export function PublicKeyID<V extends Version>(
  implementation: PublicKeyIDImplementation<V>,
): CapabilityFactory<
  'public',
  V,
  'PublicKeyID',
  (paserk: `k${V}.public.${string}`) => Promise<`k${V}.pid.${string}`>
> {
  return createOperation(implementation, 'public', 'PublicKeyID', implementationRun)
}

/**
 * Creates a composable secret PASERK ID capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @param implementation - Low-level secret PASERK ID implementation
 */
export function SecretKeyID<V extends Version>(
  implementation: SecretKeyIDImplementation<V>,
): CapabilityFactory<
  'public',
  V,
  'SecretKeyID',
  (paserk: SecretKeyIDInput<V>) => Promise<`k${V}.sid.${string}`>
> {
  return createOperation(implementation, 'public', 'SecretKeyID', implementationRun)
}

/**
 * Creates a composable wrapping-key generation capability factory for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key generation implementation for public-purpose keys
 */
export function PublicGenerateWrappingKey<V extends Version, W extends Key>(
  implementation: PublicGenerateWrappingKeyImplementation<V, W>,
): CapabilityFactory<'public', V, 'GenerateWrappingKey', (options?: KeyOptions) => Promise<W>> {
  return createOperation(
    implementation,
    'public',
    'GenerateWrappingKey',
    (value) => async (options?: KeyOptions) => await value.run(keyExtractable(options)),
  )
}

/**
 * Creates a composable wrapping-key import capability factory for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key import implementation for public-purpose keys
 */
export function PublicImportWrappingKey<V extends Version, W extends Key>(
  implementation: PublicImportWrappingKeyImplementation<V, W>,
): CapabilityFactory<
  'public',
  V,
  'ImportWrappingKey',
  (material: Uint8Array, options?: KeyOptions) => Promise<W>
> {
  return createOperation(
    implementation,
    'public',
    'ImportWrappingKey',
    (value) => async (material, options) => await value.run(material, keyExtractable(options)),
  )
}

/**
 * Creates a composable wrapping-key export capability factory for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key export implementation for public-purpose keys
 */
export function PublicExportWrappingKey<V extends Version, W extends Key>(
  implementation: PublicExportWrappingKeyImplementation<V, W>,
): CapabilityFactory<'public', V, 'ExportWrappingKey', (key: W) => Promise<Uint8Array>> {
  return createOperation(implementation, 'public', 'ExportWrappingKey', implementationRun)
}

/**
 * Creates a composable secret key-wrapping capability factory.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 * @param implementation - Low-level secret key-wrapping implementation
 */
export function PublicWrapSecretKey<
  V extends Version,
  S extends Key,
  W extends Key,
  Prefix extends string = string,
>(
  implementation: PublicWrapSecretKeyImplementation<V, S, W, Prefix>,
): CapabilityFactory<
  'public',
  V,
  'WrapSecretKey',
  (key: S, wrappingKey: W) => Promise<`k${V}.secret-wrap.${Prefix}.${string}`>
> {
  return createOperation(implementation, 'public', 'WrapSecretKey', implementationRun)
}

/**
 * Creates a composable secret key-unwrapping capability factory.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 * @param implementation - Low-level secret key-unwrapping implementation
 */
export function PublicUnwrapSecretKey<
  V extends Version,
  S extends Key,
  W extends Key,
  Prefix extends string = string,
>(
  implementation: PublicUnwrapSecretKeyImplementation<V, S, W, Prefix>,
): CapabilityFactory<
  'public',
  V,
  'UnwrapSecretKey',
  (
    paserk: `k${V}.secret-wrap.${Prefix}.${string}`,
    wrappingKey: W,
    options?: KeyOptions,
  ) => Promise<S>
> {
  return createOperation(
    implementation,
    'public',
    'UnwrapSecretKey',
    (value) => async (paserk, wrappingKey, options) =>
      await value.run(paserk, wrappingKey, keyExtractable(options)),
  )
}

/**
 * Creates a composable password-based secret key-wrapping capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `PasswordWrapOptions<V>`.
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level password-based secret key-wrapping implementation
 */
export function PublicWrapSecretKeyWithPassword<V extends Version, S extends Key>(
  implementation: PublicWrapSecretKeyWithPasswordImplementation<V, S>,
): CapabilityFactory<
  'public',
  V,
  'WrapSecretKeyWithPassword',
  <const Options extends PasswordWrapOptions<V> = PasswordWrapOptions<V>>(
    key: S,
    password: Uint8Array,
    options?: Options & Record<Exclude<keyof Options, keyof PasswordWrapOptions<V>>, never>,
  ) => Promise<`k${V}.secret-pw.${string}`>
> {
  return createOperation(
    implementation,
    'public',
    'WrapSecretKeyWithPassword',
    (value) => async (key, password, options) => {
      const resolved: PasswordWrapOptions<V> = optionsObject(options)
      validatePasswordWrapOptions(value.version, resolved)
      return await value.run(key, password, resolved)
    },
  )
}

/**
 * Creates a composable password-based secret key-unwrapping capability factory.
 *
 * @remarks
 * The installed operation's `options` argument is `PasswordUnwrapOptions<V>`.
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level password-based secret key-unwrapping implementation
 */
export function PublicUnwrapSecretKeyWithPassword<V extends Version, S extends Key>(
  implementation: PublicUnwrapSecretKeyWithPasswordImplementation<V, S>,
): CapabilityFactory<
  'public',
  V,
  'UnwrapSecretKeyWithPassword',
  <const Options extends PasswordUnwrapOptions<V> = PasswordUnwrapOptions<V>>(
    paserk: `k${V}.secret-pw.${string}`,
    password: Uint8Array,
    options?: Options & Record<Exclude<keyof Options, keyof PasswordUnwrapOptions<V>>, never>,
  ) => Promise<S>
> {
  return createOperation(
    implementation,
    'public',
    'UnwrapSecretKeyWithPassword',
    (value) => async (paserk, password, options) => {
      const resolved: PasswordUnwrapOptions<V> = optionsObject(options)
      validatePasswordUnwrapOptions(value.version, resolved)
      const extractable = booleanOption(resolved.extractable, 'extractable', false)
      const limits = { ...resolved }
      delete limits.extractable
      return await value.run(paserk, password, limits as PasswordUnwrapLimits<V>, extractable)
    },
  )
}

// ============================================================================
// Errors
// ============================================================================

/**
 * Stable machine-readable codes used by errors produced by this module.
 *
 * @category Errors
 */
export type PasetoErrorCode =
  | 'ERR_PASETO_INVALID_TOKEN'
  | 'ERR_PASERK_INVALID'
  | 'ERR_PASETO_INVALID_KEY'
  | 'ERR_PASETO_CLAIM_VALIDATION'
  | 'ERR_PASETO_UNSUPPORTED_ALGORITHM'

/**
 * Base class for errors produced by this module.
 *
 * @category Errors
 * @typeParam C - Stable machine-readable error code
 */
export class PasetoError<C extends PasetoErrorCode = PasetoErrorCode> extends Error {
  /** Stable machine-readable error code. */
  readonly code: C

  /**
   * @param code - Stable machine-readable error code
   * @param message - Human-readable error message
   * @param options - Error construction options
   */
  constructor(code: C, message: string, options?: ErrorOptions) {
    super(message, options)
    this.code = code
    this.name = this.constructor.name
  }
}

/**
 * The token is malformed or failed authentication.
 *
 * @category Errors
 */
export class InvalidTokenError extends PasetoError<'ERR_PASETO_INVALID_TOKEN'> {
  /**
   * @param message - Human-readable error message
   * @param options - Error construction options
   */
  constructor(message: string = 'Invalid token', options?: ErrorOptions) {
    super('ERR_PASETO_INVALID_TOKEN', message, options)
  }
}

/**
 * The PASERK is malformed or failed authentication.
 *
 * @category Errors
 */
export class InvalidPASERKError extends PasetoError<'ERR_PASERK_INVALID'> {
  /**
   * @param message - Human-readable error message
   * @param options - Error construction options
   */
  constructor(message: string = 'Invalid PASERK', options?: ErrorOptions) {
    super('ERR_PASERK_INVALID', message, options)
  }
}

/**
 * The key is malformed, unavailable for an operation, or belongs to another protocol tuple.
 *
 * @category Errors
 */
export class InvalidKeyError extends PasetoError<'ERR_PASETO_INVALID_KEY'> {
  /**
   * @param message - Human-readable error message
   * @param options - Error construction options
   */
  constructor(message: string = 'Invalid key', options?: ErrorOptions) {
    super('ERR_PASETO_INVALID_KEY', message, options)
  }
}

/**
 * An authenticated token contains claims that fail validation.
 *
 * @category Errors
 */
export class ClaimValidationError extends PasetoError<'ERR_PASETO_CLAIM_VALIDATION'> {
  /** Claim whose validation failed, when applicable. */
  readonly claim?: string

  /**
   * @param message - Human-readable error message
   * @param claim - Claim whose validation failed
   * @param options - Error construction options
   */
  constructor(message: string, claim?: string, options?: ErrorOptions) {
    super('ERR_PASETO_CLAIM_VALIDATION', message, options)
    if (claim !== undefined) this.claim = claim
  }
}

/**
 * The current runtime does not provide a required cryptographic primitive.
 *
 * @category Errors
 */
export class UnsupportedAlgorithmError extends PasetoError<'ERR_PASETO_UNSUPPORTED_ALGORITHM'> {
  /**
   * @param message - Human-readable error message
   * @param options - Error construction options
   */
  constructor(message: string, options?: ErrorOptions) {
    super('ERR_PASETO_UNSUPPORTED_ALGORITHM', message, options)
  }
}

function normalizePasetoError(cause: unknown): unknown {
  if (cause instanceof PasetoError || cause === null || typeof cause !== 'object') return cause
  const error = cause as {
    readonly code?: unknown
    readonly message?: unknown
    readonly claim?: unknown
  }
  if (typeof error.message !== 'string') return cause
  const options: ErrorOptions = { cause }
  switch (error.code) {
    case 'ERR_PASETO_INVALID_TOKEN':
      return new InvalidTokenError(error.message, options)
    case 'ERR_PASERK_INVALID':
      return new InvalidPASERKError(error.message, options)
    case 'ERR_PASETO_INVALID_KEY':
      return new InvalidKeyError(error.message, options)
    case 'ERR_PASETO_CLAIM_VALIDATION':
      return new ClaimValidationError(
        error.message,
        typeof error.claim === 'string' ? error.claim : undefined,
        options,
      )
    case 'ERR_PASETO_UNSUPPORTED_ALGORITHM':
      return new UnsupportedAlgorithmError(error.message, options)
    default:
      return cause
  }
}

// ============================================================================
// Byte and encoding utilities
// ============================================================================

const encoder = /* @__PURE__ */ new TextEncoder()
const decoder = /* @__PURE__ */ new TextDecoder('utf-8', { fatal: true })
const empty = /* @__PURE__ */ new Uint8Array()

function checkBytes(value: unknown, name: string, length?: number): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer)) {
    throw new TypeError(`\"${name}\" must be a Uint8Array backed by an ArrayBuffer`)
  }
  if (length !== undefined && value.byteLength !== length) {
    throw new TypeError(`\"${name}\" must be ${length} bytes`)
  }
}

function copyBytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value)
}

function optionalBytes(value: Uint8Array | undefined, name: string): Uint8Array {
  if (value === undefined) return empty
  checkBytes(value, name)
  return copyBytes(value)
}

function concat(...pieces: readonly Uint8Array[]): Uint8Array {
  let length = 0
  for (const piece of pieces) length += piece.byteLength
  const output = new Uint8Array(length)
  let offset = 0
  for (const piece of pieces) {
    output.set(piece, offset)
    offset += piece.byteLength
  }
  return output
}

function ascii(value: string): Uint8Array {
  return encoder.encode(value)
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  let mismatch = left.byteLength ^ right.byteLength
  const length = Math.max(left.byteLength, right.byteLength)
  for (let i = 0; i < length; i++) {
    mismatch |=
      (left[i % Math.max(left.byteLength, 1)] ?? 0) ^
      (right[i % Math.max(right.byteLength, 1)] ?? 0)
  }
  return mismatch === 0
}

function fromBase64(input: string): Uint8Array {
  input = input.replaceAll('-', '+').replaceAll('_', '/')
  const binary = atob(input)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

function toBase64Url(input: Uint8Array): string {
  let binary = ''
  const chunk = 0x8000
  for (let offset = 0; offset < input.byteLength; offset += chunk) {
    binary += String.fromCharCode(...input.subarray(offset, offset + chunk))
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')
}

function toB64u(input: Uint8Array): string {
  // @ts-ignore Uint8Array Base64 methods are not yet in every TypeScript library.
  return input.toBase64?.({ alphabet: 'base64url', omitPadding: true }) || toBase64Url(input)
}

function b64u(input: string): Uint8Array {
  // @ts-ignore Uint8Array Base64 methods are not yet in every TypeScript library.
  return Uint8Array.fromBase64?.(input, { alphabet: 'base64url' }) || fromBase64(input)
}

function decodeBase64url(input: string, name: string): Uint8Array {
  if (typeof input !== 'string' || !/^[A-Za-z0-9_-]*$/u.test(input) || input.length % 4 === 1) {
    throw new InvalidTokenError(`Invalid base64url in ${name}`)
  }
  try {
    const output = b64u(input)
    if (toB64u(output) !== input) throw new Error('non-canonical')
    return output
  } catch (cause) {
    throw new InvalidTokenError(`Invalid base64url in ${name}`, { cause })
  }
}

function le64(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new RangeError('value must be a safe integer')
  const output = new Uint8Array(8)
  let remainder = value
  for (let i = 0; i < 8; i++) {
    output[i] = remainder & 0xff
    remainder = Math.floor(remainder / 256)
  }
  output[7] = output[7]! & 0x7f
  return output
}

/**
 * Pre-Authentication Encoding (PAE).
 *
 * @category Utilities
 * @param pieces - Byte strings to encode
 * @see https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
 */
export function PAE(pieces: readonly Uint8Array[]): Uint8Array {
  if (!Array.isArray(pieces)) throw new TypeError('"pieces" must be an array')
  const encoded: Uint8Array[] = [le64(pieces.length)]
  for (const [index, piece] of pieces.entries()) {
    checkBytes(piece, `pieces[${index}]`)
    encoded.push(le64(piece.byteLength), piece)
  }
  return concat(...encoded)
}

// ============================================================================
// Claim processing
// ============================================================================

function parseClaims(input: Uint8Array): Claims {
  let json: string
  try {
    json = decoder.decode(input)
  } catch (cause) {
    throw new InvalidTokenError('Claims are not valid UTF-8', { cause })
  }
  let claims: unknown
  try {
    claims = JSON.parse(json)
  } catch (cause) {
    throw new InvalidTokenError('Claims are not valid JSON', { cause })
  }
  if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new InvalidTokenError('Claims must be a JSON object')
  }
  return claims as Claims
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new TypeError(`\"${name}\" must be a positive safe integer`)
  return value
}

function nonnegativeNumber(value: number, name: string): number {
  if (!Number.isFinite(value) || value < 0)
    throw new TypeError(`\"${name}\" must be a non-negative number`)
  return value
}

function optionsObject<T extends object>(value: T | undefined): T {
  if (value === undefined) return {} as T
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('"options" must be an object')
  }
  return value
}

function booleanOption(value: unknown, name: string, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue
  if (typeof value !== 'boolean') throw new TypeError(`\"${name}\" must be a boolean`)
  return value
}

function stringOption(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined
  if (typeof value !== 'string') throw new TypeError(`\"${name}\" must be a string`)
  return value
}

function currentDate(value: Date | undefined): Date {
  const date = value === undefined ? new Date() : value
  if (!(date instanceof Date) || Number.isNaN(date.valueOf()))
    throw new TypeError('"now" must be a valid Date')
  return new Date(date)
}

function numericDate(value: Date): string {
  return value.toISOString().replace(/\.\d{3}Z$/u, 'Z')
}

const rfc3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/u

function validDay(year: number, month: number, day: number): boolean {
  if (month < 1 || month > 12 || day < 1) return false
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const days =
    month === 2
      ? leapYear
        ? 29
        : 28
      : month === 4 || month === 6 || month === 9 || month === 11
        ? 30
        : 31
  return day <= days
}

function claimDate(claims: Claims, name: 'exp' | 'iat' | 'nbf'): number | undefined {
  const value = claims[name]
  if (value === undefined) return undefined
  if (typeof value !== 'string') {
    throw new ClaimValidationError(`\"${name}\" must be an RFC 3339 date-time string`, name)
  }
  const match = rfc3339.exec(value)
  if (match === null) {
    throw new ClaimValidationError(`\"${name}\" must be an RFC 3339 date-time string`, name)
  }
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const offsetHour = match[10] === undefined ? 0 : Number(match[10])
  const offsetMinute = match[11] === undefined ? 0 : Number(match[11])
  if (
    !validDay(year, month, day) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new ClaimValidationError(`\"${name}\" must be a valid RFC 3339 date-time`, name)
  }
  const milliseconds = Number((match[7] ?? '').padEnd(3, '0').slice(0, 3))
  const instant = new Date(0)
  instant.setUTCFullYear(year, month - 1, day)
  instant.setUTCHours(hour, minute, second, milliseconds)
  let timestamp = instant.valueOf()
  if (match[8] !== 'Z') {
    const direction = match[9] === '+' ? 1 : -1
    timestamp -= direction * (offsetHour * 60 + offsetMinute) * 60_000
  }
  return timestamp
}

function stringClaim(claims: Claims, name: 'aud' | 'iss' | 'sub' | 'jti'): string | undefined {
  const value = claims[name]
  if (value === undefined) return undefined
  if (typeof value !== 'string')
    throw new ClaimValidationError(`\"${name}\" must be a string`, name)
  return value
}

function prepareClaims(input: object, options: ProduceOptionsRuntime): Uint8Array {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('"claims" must be a JSON object')
  }
  const now = currentDate(options.now)
  const claims = { ...input } as Claims
  const addIssuedAt = booleanOption(options.addIssuedAt, 'addIssuedAt', true)
  const nonExpiring = booleanOption(options.nonExpiring, 'nonExpiring', false)
  const expiresIn =
    options.expiresIn === undefined ? undefined : nonnegativeNumber(options.expiresIn, 'expiresIn')
  if (addIssuedAt && claims.iat === undefined) claims.iat = numericDate(now)
  if (nonExpiring) {
    if (expiresIn !== undefined)
      throw new TypeError('"expiresIn" and "nonExpiring" are mutually exclusive')
    delete claims.exp
  } else if (expiresIn !== undefined) {
    claims.exp = numericDate(new Date(now.valueOf() + expiresIn * 1000))
  } else if (claims.exp === undefined) {
    claims.exp = numericDate(new Date(now.valueOf() + 3_600_000))
  }
  for (const name of ['aud', 'iss', 'sub', 'jti'] as const) stringClaim(claims, name)
  for (const name of ['exp', 'iat', 'nbf'] as const) claimDate(claims, name)
  let json: string | undefined
  try {
    json = JSON.stringify(claims)
  } catch (cause) {
    throw new TypeError('"claims" must be JSON serializable', { cause })
  }
  if (json === undefined) throw new TypeError('"claims" must be JSON serializable')
  const encoded = encoder.encode(json)
  parseClaims(encoded)
  return encoded
}

function expectedValues(value: string | readonly string[]): readonly string[] {
  if (typeof value === 'string') return [value]
  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    value.some((entry) => typeof entry !== 'string')
  ) {
    throw new TypeError('Expected claim values must be a string or non-empty array of strings')
  }
  return value
}

function validateClaims(claims: Claims, options: ConsumeOptionsRuntime): void {
  const now = currentDate(options.now).valueOf()
  const tolerance = nonnegativeNumber(options.clockTolerance ?? 0, 'clockTolerance') * 1000
  const allowNonExpiring = booleanOption(options.allowNonExpiring, 'allowNonExpiring', false)
  const exp = claimDate(claims, 'exp')
  const iat = claimDate(claims, 'iat')
  const nbf = claimDate(claims, 'nbf')
  for (const name of ['aud', 'iss', 'sub', 'jti'] as const) stringClaim(claims, name)

  if (exp === undefined && !allowNonExpiring) {
    throw new ClaimValidationError('Missing required "exp" claim', 'exp')
  }
  if (exp !== undefined && now > exp + tolerance) {
    throw new ClaimValidationError('Token has expired', 'exp')
  }
  if (nbf !== undefined && now + tolerance < nbf) {
    throw new ClaimValidationError('Token is not active yet', 'nbf')
  }
  if (iat !== undefined && now + tolerance < iat) {
    throw new ClaimValidationError('Token was issued in the future', 'iat')
  }
  if (options.maxTokenAge !== undefined) {
    const maximum = nonnegativeNumber(options.maxTokenAge, 'maxTokenAge') * 1000
    if (iat === undefined) throw new ClaimValidationError('Missing required "iat" claim', 'iat')
    if (now - tolerance > iat + maximum) throw new ClaimValidationError('Token is too old', 'iat')
  }
  const comparisons: ReadonlyArray<readonly [keyof ConsumeOptionsRuntime, 'aud' | 'iss']> = [
    ['audience', 'aud'],
    ['issuer', 'iss'],
  ]
  for (const [option, claim] of comparisons) {
    const expected = options[option]
    if (
      expected !== undefined &&
      !expectedValues(expected as string | readonly string[]).includes(claims[claim] as string)
    ) {
      throw new ClaimValidationError(`Unexpected \"${claim}\" claim`, claim)
    }
  }
  const subject = stringOption(options.subject, 'subject')
  if (subject !== undefined && claims.sub !== subject) {
    throw new ClaimValidationError('Unexpected "sub" claim', 'sub')
  }
  const tokenIdentifier = stringOption(options.tokenIdentifier, 'tokenIdentifier')
  if (tokenIdentifier !== undefined && claims.jti !== tokenIdentifier) {
    throw new ClaimValidationError('Unexpected "jti" claim', 'jti')
  }
  if (options.requiredClaims !== undefined) {
    if (
      !Array.isArray(options.requiredClaims) ||
      options.requiredClaims.some((name) => typeof name !== 'string')
    ) {
      throw new TypeError('"requiredClaims" must be an array of strings')
    }
    for (const name of options.requiredClaims) {
      if (!Object.hasOwn(claims, name))
        throw new ClaimValidationError(`Missing required \"${name}\" claim`, name)
    }
  }
}

// ============================================================================
// Web Cryptography helpers
// ============================================================================

function webCryptoBytes(input: Uint8Array): Uint8Array<ArrayBuffer> {
  checkBytes(input, 'Web Cryptography input')
  return input as Uint8Array<ArrayBuffer>
}

function unsupportedPrimitive(name: string, cause?: unknown): UnsupportedAlgorithmError {
  return new UnsupportedAlgorithmError(
    `${name} is not available from the Web Cryptography runtime API`,
    { cause },
  )
}

/**
 * Web Cryptography Argon2id implementation.
 *
 * A custom {@link Argon2idFactory} can be used by third-party protocol implementations in runtimes
 * without Web Cryptography.
 *
 * @category Password-Based Key Wrapping
 */
export const KDF_ARGON2ID: Argon2idFactory = function (): Argon2id {
  return {
    type: 'KDF',
    name: 'Argon2id',
    async Derive(password, salt, parameters) {
      checkBytes(password, 'password')
      checkBytes(salt, 'salt')
      const memory = positiveInteger(parameters.memory, 'memory')
      const passes = positiveInteger(parameters.passes, 'passes')
      const parallelism = positiveInteger(parameters.parallelism, 'parallelism')
      const length = positiveInteger(parameters.length, 'length')
      if (memory % 1024 !== 0) {
        throw new RangeError('"memory" must be a whole number of kibibytes')
      }
      if (length > Math.floor(Number.MAX_SAFE_INTEGER / 8)) {
        throw new RangeError('"length" is too large')
      }
      try {
        const key = await crypto.subtle.importKey(
          'raw-secret' as 'raw',
          webCryptoBytes(password),
          { name: 'Argon2id' },
          false,
          ['deriveBits'],
        )
        return new Uint8Array(
          await crypto.subtle.deriveBits(
            {
              name: 'Argon2id',
              nonce: webCryptoBytes(salt),
              memory: memory / 1024,
              passes,
              parallelism,
              version: 0x13,
            } as AlgorithmIdentifier,
            key,
            length * 8,
          ),
        )
      } catch (cause) {
        if (
          cause instanceof TypeError ||
          (typeof DOMException !== 'undefined' &&
            cause instanceof DOMException &&
            cause.name === 'NotSupportedError')
        ) {
          throw unsupportedPrimitive('Argon2id', cause)
        }
        throw cause
      }
    },
  }
}

// ============================================================================
// PASETO token formatting
// ============================================================================

interface ParsedToken {
  payload: Uint8Array
  footer: Uint8Array
}

function tokenHeader(version: Version, purpose: 'local' | 'public'): Uint8Array {
  return ascii(`v${version}.${purpose}.`)
}

function formatToken(header: Uint8Array, payload: Uint8Array, footer: Uint8Array): string {
  const base = `${decoder.decode(header)}${toB64u(payload)}`
  return footer.byteLength === 0 ? base : `${base}.${toB64u(footer)}`
}

function parseToken(
  token: string,
  version: Version,
  purpose: 'local' | 'public',
  options: ConsumeOptionsRuntime,
): ParsedToken {
  if (typeof token !== 'string') throw new TypeError('"token" must be a string')
  const parts = token.split('.')
  if (parts.length !== 3 && parts.length !== 4) throw new InvalidTokenError('Malformed token')
  if (parts[0] !== `v${version}` || parts[1] !== purpose || parts[2] === '') {
    throw new InvalidTokenError(`Expected a v${version}.${purpose} token`)
  }
  if (parts.length === 4 && parts[3] === '') throw new InvalidTokenError('Empty footer segment')
  const payload = decodeBase64url(parts[2]!, 'token payload')
  const footer = parts[3] === undefined ? empty : decodeBase64url(parts[3], 'token footer')
  if (options.footer !== undefined) {
    checkBytes(options.footer, 'footer')
    if (!equalBytes(footer, options.footer))
      throw new InvalidTokenError('Token footer does not match')
  }
  return { payload, footer }
}

/**
 * Extracts a token footer without authenticating it.
 *
 * The returned bytes are suitable for routing to a key, but must not be trusted until the token is
 * successfully decrypted or verified. This function validates the token header and framing but
 * deliberately does not decode or validate its payload.
 *
 * @category Utilities
 * @param token - PASETO token whose footer will be decoded
 */
export function InspectFooter(token: string): Uint8Array {
  if (typeof token !== 'string') throw new TypeError('"token" must be a string')
  const parts = token.split('.')
  if (parts.length !== 3 && parts.length !== 4) throw new InvalidTokenError('Malformed token')
  if (
    !/^v[1-4]$/u.test(parts[0]!) ||
    (parts[1] !== 'local' && parts[1] !== 'public') ||
    parts[2] === ''
  ) {
    throw new InvalidTokenError('Malformed token header')
  }
  if (parts.length === 4 && parts[3] === '') throw new InvalidTokenError('Empty footer segment')
  return parts[3] === undefined ? copyBytes(empty) : decodeBase64url(parts[3], 'token footer')
}

function implicitAssertion(version: Version, options: object): Uint8Array {
  if (version < 3 && 'implicitAssertion' in options) {
    throw new TypeError(`v${version} does not support implicit assertions`)
  }
  const value =
    'implicitAssertion' in options
      ? (options as { implicitAssertion?: Uint8Array }).implicitAssertion
      : undefined
  return optionalBytes(value, 'implicitAssertion')
}

function rejectPasswordOption(version: Version, options: object, name: string): void {
  if (name in options) {
    throw new TypeError(`PASERK v${version} does not support "${name}"`)
  }
}

function validatePasswordWrapOptions(version: Version, options: object): void {
  if (version === 1 || version === 3) {
    rejectPasswordOption(version, options, 'memory')
    rejectPasswordOption(version, options, 'passes')
    rejectPasswordOption(version, options, 'parallelism')
    const iterations = (options as PasswordWrapOptions<1>).iterations
    if (iterations !== undefined) positiveInteger(iterations, 'iterations')
  } else {
    rejectPasswordOption(version, options, 'iterations')
    const { memory, passes, parallelism } = options as PasswordWrapOptions<2>
    if (memory !== undefined) positiveInteger(memory, 'memory')
    if (passes !== undefined) positiveInteger(passes, 'passes')
    if (parallelism !== undefined) positiveInteger(parallelism, 'parallelism')
  }
}

function validatePasswordUnwrapOptions(version: Version, options: object): void {
  if (version === 1 || version === 3) {
    rejectPasswordOption(version, options, 'maxMemory')
    rejectPasswordOption(version, options, 'maxPasses')
    rejectPasswordOption(version, options, 'maxParallelism')
    const maxIterations = (options as PasswordUnwrapOptions<1>).maxIterations
    if (maxIterations !== undefined) positiveInteger(maxIterations, 'maxIterations')
  } else {
    rejectPasswordOption(version, options, 'maxIterations')
    const { maxMemory, maxPasses, maxParallelism } = options as PasswordUnwrapOptions<2>
    if (maxMemory !== undefined) positiveInteger(maxMemory, 'maxMemory')
    if (maxPasses !== undefined) positiveInteger(maxPasses, 'maxPasses')
    if (maxParallelism !== undefined) positiveInteger(maxParallelism, 'maxParallelism')
  }
}

// ============================================================================
// Capability-dependent protocol composition
// ============================================================================

/**
 * Operation names supported by local-purpose protocol composition.
 *
 * @category Protocol Composition
 */
export type LocalOperation =
  | 'GenerateKey'
  | 'Encrypt'
  | 'Decrypt'
  | 'ImportKey'
  | 'ExportKey'
  | 'KeyID'
  | 'GenerateWrappingKey'
  | 'ImportWrappingKey'
  | 'ExportWrappingKey'
  | 'WrapKey'
  | 'UnwrapKey'
  | 'WrapKeyWithPassword'
  | 'UnwrapKeyWithPassword'
  | 'GenerateSealingKeyPair'
  | 'ImportSealingPublicKey'
  | 'ImportSealingSecretKey'
  | 'ExportSealingPublicKey'
  | 'ExportSealingSecretKey'
  | 'SealKey'
  | 'UnsealKey'

/**
 * Operation names supported by public-purpose protocol composition.
 *
 * @category Protocol Composition
 */
export type PublicOperation =
  | 'GenerateKeyPair'
  | 'Sign'
  | 'Verify'
  | 'ImportPublicKey'
  | 'ExportPublicKey'
  | 'ImportSecretKey'
  | 'ExportSecretKey'
  | 'GetPublicKey'
  | 'PublicKeyID'
  | 'SecretKeyID'
  | 'GenerateWrappingKey'
  | 'ImportWrappingKey'
  | 'ExportWrappingKey'
  | 'WrapSecretKey'
  | 'UnwrapSecretKey'
  | 'WrapSecretKeyWithPassword'
  | 'UnwrapSecretKeyWithPassword'

type BivariantOperation<Arguments extends unknown[], Result> = {
  bivarianceHack(...args: Arguments): Result
}['bivarianceHack']

type BivariantProduceOperation<V extends Version> = {
  bivarianceHack<
    const C extends object,
    const Options extends ProduceOptions<V> = ProduceOptions<V>,
  >(
    key: Key,
    claims: ClaimsInput<C>,
    options?: StrictOptions<ProduceOptions<V>, Options>,
  ): Promise<string>
}['bivarianceHack']

/**
 * Installed method signature for a local-purpose operation after its factory is composed.
 *
 * @typeParam V - PASETO and PASERK protocol version
 * @typeParam O - Local-purpose operation name
 */
type LocalOperationMethod<V extends Version, O extends LocalOperation> = {
  GenerateKey: BivariantOperation<[options?: KeyOptions], Promise<Key>>
  Encrypt: BivariantProduceOperation<V>
  Decrypt: BivariantOperation<
    [key: Key, token: string, options?: ConsumeOptions<V>],
    Promise<TokenResult>
  >
  ImportKey: BivariantOperation<[paserk: LocalPASERK<V>, options?: KeyOptions], Promise<Key>>
  ExportKey: BivariantOperation<[key: Key], Promise<LocalPASERK<V>>>
  KeyID: BivariantOperation<[paserk: LocalKeyIDInput<V>], Promise<LocalIdPASERK<V>>>
  GenerateWrappingKey: BivariantOperation<[options?: KeyOptions], Promise<Key>>
  ImportWrappingKey: BivariantOperation<[material: Uint8Array, options?: KeyOptions], Promise<Key>>
  ExportWrappingKey: BivariantOperation<[key: Key], Promise<Uint8Array>>
  WrapKey: BivariantOperation<[key: Key, wrappingKey: Key], Promise<WrappedLocalPASERK<V>>>
  UnwrapKey: BivariantOperation<
    [paserk: WrappedLocalPASERK<V>, wrappingKey: Key, options?: KeyOptions],
    Promise<Key>
  >
  WrapKeyWithPassword: BivariantOperation<
    [key: Key, password: Uint8Array, options?: PasswordWrapOptions<V>],
    Promise<PasswordWrappedLocalPASERK<V>>
  >
  UnwrapKeyWithPassword: BivariantOperation<
    [
      paserk: PasswordWrappedLocalPASERK<V>,
      password: Uint8Array,
      options?: PasswordUnwrapOptions<V>,
    ],
    Promise<Key>
  >
  GenerateSealingKeyPair: BivariantOperation<[options?: KeyOptions], Promise<KeyPair<Key, Key>>>
  ImportSealingPublicKey: BivariantOperation<[material: Uint8Array], Promise<Key>>
  ImportSealingSecretKey: BivariantOperation<
    [material: Uint8Array, options?: KeyOptions],
    Promise<Key>
  >
  ExportSealingPublicKey: BivariantOperation<[key: Key], Promise<Uint8Array>>
  ExportSealingSecretKey: BivariantOperation<[key: Key], Promise<Uint8Array>>
  SealKey: BivariantOperation<[key: Key, recipient: Key], Promise<SealedLocalPASERK<V>>>
  UnsealKey: BivariantOperation<
    [paserk: SealedLocalPASERK<V>, recipient: Key, options?: KeyOptions],
    Promise<Key>
  >
}[O]

/**
 * Installed method signature for a public-purpose operation after its factory is composed.
 *
 * @typeParam V - PASETO and PASERK protocol version
 * @typeParam O - Public-purpose operation name
 */
type PublicOperationMethod<V extends Version, O extends PublicOperation> = {
  GenerateKeyPair: BivariantOperation<[options?: KeyOptions], Promise<KeyPair<Key, Key>>>
  Sign: BivariantProduceOperation<V>
  Verify: BivariantOperation<
    [key: Key, token: string, options?: ConsumeOptions<V>],
    Promise<TokenResult>
  >
  ImportPublicKey: BivariantOperation<[paserk: PublicPASERK<V>], Promise<Key>>
  ExportPublicKey: BivariantOperation<[key: Key], Promise<PublicPASERK<V>>>
  ImportSecretKey: BivariantOperation<[paserk: SecretPASERK<V>, options?: KeyOptions], Promise<Key>>
  ExportSecretKey: BivariantOperation<[key: Key], Promise<SecretPASERK<V>>>
  GetPublicKey: BivariantOperation<[key: Key], Promise<Key>>
  PublicKeyID: BivariantOperation<[paserk: PublicPASERK<V>], Promise<PublicIdPASERK<V>>>
  SecretKeyID: BivariantOperation<[paserk: SecretKeyIDInput<V>], Promise<SecretIdPASERK<V>>>
  GenerateWrappingKey: BivariantOperation<[options?: KeyOptions], Promise<Key>>
  ImportWrappingKey: BivariantOperation<[material: Uint8Array, options?: KeyOptions], Promise<Key>>
  ExportWrappingKey: BivariantOperation<[key: Key], Promise<Uint8Array>>
  WrapSecretKey: BivariantOperation<[key: Key, wrappingKey: Key], Promise<WrappedSecretPASERK<V>>>
  UnwrapSecretKey: BivariantOperation<
    [paserk: WrappedSecretPASERK<V>, wrappingKey: Key, options?: KeyOptions],
    Promise<Key>
  >
  WrapSecretKeyWithPassword: BivariantOperation<
    [key: Key, password: Uint8Array, options?: PasswordWrapOptions<V>],
    Promise<PasswordWrappedSecretPASERK<V>>
  >
  UnwrapSecretKeyWithPassword: BivariantOperation<
    [
      paserk: PasswordWrappedSecretPASERK<V>,
      password: Uint8Array,
      options?: PasswordUnwrapOptions<V>,
    ],
    Promise<Key>
  >
}[O]

type LocalCapabilityMethod<V extends Version, O extends LocalOperation> = LocalOperation extends O
  ? OperationMethod
  : LocalOperationMethod<V, O>

type PublicCapabilityMethod<
  V extends Version,
  O extends PublicOperation,
> = PublicOperation extends O ? OperationMethod : PublicOperationMethod<V, O>

/**
 * One local-purpose capability factory accepted by {@link LocalProtocol}.
 *
 * When `O` is a specific operation, `R` defaults to that operation's callable signature. Supply `R`
 * to retain a more specific signature for a custom key representation.
 *
 * @category Protocol Composition
 * @typeParam V - PASETO and PASERK protocol version
 * @typeParam O - Local-purpose operation name
 * @typeParam R - Installed operation signature
 */
export type LocalCapabilityFactory<
  V extends Version = Version,
  O extends LocalOperation = LocalOperation,
  R extends (...args: never[]) => unknown = LocalCapabilityMethod<V, O>,
> = CapabilityFactory<'local', V, O, R>

/**
 * One public-purpose capability factory accepted by {@link PublicProtocol}.
 *
 * When `O` is a specific operation, `R` defaults to that operation's callable signature. Supply `R`
 * to retain a more specific signature for a custom key representation.
 *
 * @category Protocol Composition
 * @typeParam V - PASETO and PASERK protocol version
 * @typeParam O - Public-purpose operation name
 * @typeParam R - Installed operation signature
 */
export type PublicCapabilityFactory<
  V extends Version = Version,
  O extends PublicOperation = PublicOperation,
  R extends (...args: never[]) => unknown = PublicCapabilityMethod<V, O>,
> = CapabilityFactory<'public', V, O, R>

/**
 * A non-empty tuple of local-purpose capability factories.
 *
 * @category Protocol Composition
 * @typeParam V - PASETO and PASERK protocol versions permitted for tuple elements
 */
export type LocalProtocolFactories<V extends Version = Version> = readonly [
  LocalCapabilityFactory<V>,
  ...LocalCapabilityFactory<V>[],
]

/**
 * A non-empty tuple of public-purpose capability factories.
 *
 * @category Protocol Composition
 * @typeParam V - PASETO and PASERK protocol versions permitted for tuple elements
 */
export type PublicProtocolFactories<V extends Version = Version> = readonly [
  PublicCapabilityFactory<V>,
  ...PublicCapabilityFactory<V>[],
]

/**
 * Extracts the literal protocol version carried by a capability factory.
 *
 * @typeParam F - Capability factory type
 */
type CapabilityVersion<F> = F extends () => Readonly<{ readonly version: infer V extends Version }>
  ? V
  : never

/**
 * Compile-time constraint requiring a factory tuple to carry one literal protocol version.
 *
 * @typeParam F - Capability factory tuple
 */
type SameVersionFactories<F extends readonly unknown[]> = F extends readonly [unknown]
  ? unknown
  : [CapabilityVersion<F[number]>] extends [never]
    ? never
    : [CapabilityVersion<F[number]>] extends [1]
      ? unknown
      : [CapabilityVersion<F[number]>] extends [2]
        ? unknown
        : [CapabilityVersion<F[number]>] extends [3]
          ? unknown
          : [CapabilityVersion<F[number]>] extends [4]
            ? unknown
            : never

/**
 * Compile-time constraint requiring every factory in a tuple to select a different operation.
 *
 * @typeParam F - Capability factory tuple
 * @typeParam Seen - Operation names already encountered during tuple traversal
 */
type UniqueOperationFactories<
  F extends readonly unknown[],
  Seen extends PropertyKey = never,
> = F extends readonly [infer Head, ...infer Tail]
  ? Head extends () => Readonly<{ readonly operation: infer O extends PropertyKey }>
    ? O extends Seen
      ? never
      : UniqueOperationFactories<Tail, Seen | O>
    : never
  : unknown

/**
 * A local protocol exposing exactly the selected capabilities.
 *
 * @category Protocol Composition
 * @typeParam F - Non-empty tuple of selected local-purpose capability factories
 */
export type LocalProtocolInstance<F extends LocalProtocolFactories> = Readonly<
  {
    readonly version: F[number] extends () => Readonly<{
      readonly version: infer V extends Version
    }>
      ? V
      : never
    readonly purpose: 'local'
  } & {
    [
      O in LocalOperation as {
        [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
          Readonly<Record<K, () => Readonly<{ readonly purpose: 'local'; readonly operation: O }>>>,
        ]
          ? O
          : never
      }[Exclude<keyof F, keyof (readonly unknown[])>]
    ]: {
      [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
        Readonly<Record<K, () => Readonly<{ readonly purpose: 'local'; readonly operation: O }>>>,
      ]
        ? Extract<
            ReturnType<Extract<F[K], LocalCapabilityFactory>>,
            Readonly<{ readonly run: (...args: never[]) => unknown }>
          >['run']
        : never
    }[Exclude<keyof F, keyof (readonly unknown[])>]
  }
>

/**
 * A public protocol exposing exactly the selected capabilities.
 *
 * @category Protocol Composition
 * @typeParam F - Non-empty tuple of selected public-purpose capability factories
 */
export type PublicProtocolInstance<F extends PublicProtocolFactories> = Readonly<
  {
    readonly version: F[number] extends () => Readonly<{
      readonly version: infer V extends Version
    }>
      ? V
      : never
    readonly purpose: 'public'
  } & {
    [
      O in PublicOperation as {
        [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
          Readonly<
            Record<K, () => Readonly<{ readonly purpose: 'public'; readonly operation: O }>>
          >,
        ]
          ? O
          : never
      }[Exclude<keyof F, keyof (readonly unknown[])>]
    ]: {
      [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
        Readonly<Record<K, () => Readonly<{ readonly purpose: 'public'; readonly operation: O }>>>,
      ]
        ? Extract<
            ReturnType<Extract<F[K], PublicCapabilityFactory>>,
            Readonly<{ readonly run: (...args: never[]) => unknown }>
          >['run']
        : never
    }[Exclude<keyof F, keyof (readonly unknown[])>]
  }
>

/**
 * Constructor for a capability-selected local protocol.
 *
 * @inline
 */
interface LocalProtocolConstructor {
  /**
   * Creates a local-purpose protocol exposing exactly the selected capabilities. `F` is inferred as
   * the non-empty tuple of supplied factory arguments.
   *
   * @typeParam F - Non-empty tuple of selected local-purpose capability factories
   * @param factories - Same-version local-purpose capability factories with unique operations
   * @inlineType CapabilityVersion
   * @inlineType SameVersionFactories
   * @inlineType UniqueOperationFactories
   */
  new <const F extends LocalProtocolFactories>(
    ...factories: F & SameVersionFactories<F> & UniqueOperationFactories<F>
  ): LocalProtocolInstance<F>
}

/**
 * Constructor for a capability-selected public protocol.
 *
 * @inline
 */
interface PublicProtocolConstructor {
  /**
   * Creates a public-purpose protocol exposing exactly the selected capabilities. `F` is inferred
   * as the non-empty tuple of supplied factory arguments.
   *
   * @typeParam F - Non-empty tuple of selected public-purpose capability factories
   * @param factories - Same-version public-purpose capability factories with unique operations
   * @inlineType CapabilityVersion
   * @inlineType SameVersionFactories
   * @inlineType UniqueOperationFactories
   */
  new <const F extends PublicProtocolFactories>(
    ...factories: F & SameVersionFactories<F> & UniqueOperationFactories<F>
  ): PublicProtocolInstance<F>
}

function keyExtractable(options: KeyOptions | undefined): boolean {
  const resolved = optionsObject(options)
  return booleanOption(resolved.extractable, 'extractable', false)
}

interface RuntimeCapability {
  readonly purpose: Purpose
  readonly version: Version
  readonly operation: string
  readonly run: OperationMethod
}

function loadCapability(
  value: unknown,
  purpose: Purpose,
  version: Version | undefined,
): RuntimeCapability {
  let operation: string | undefined
  try {
    if (typeof value !== 'function') throw new TypeError('capability factory must be a function')
    if ((value as unknown as Record<PropertyKey, unknown>)[capabilityFactoryMarker] !== true) {
      throw new TypeError('capability factory is not recognized; use a paseto operation creator')
    }
    const capability = value()
    if (capability === null || typeof capability !== 'object') {
      throw new TypeError('capability factory must return an object')
    }
    const record = capability as Record<string, unknown>
    if (typeof record.operation !== 'string' || record.operation.length === 0) {
      throw new TypeError('capability operation is invalid')
    }
    operation = record.operation
    if (record.purpose !== purpose) throw new TypeError('capability purpose does not match')
    if (!validVersion(record.version)) throw new TypeError('capability version is invalid')
    if (version !== undefined && record.version !== version) {
      throw new TypeError('capability version does not match')
    }
    if (typeof record.run !== 'function') throw new TypeError('capability run must be a function')
    return record as unknown as RuntimeCapability
  } catch (cause) {
    throw new TypeError(
      operation === undefined ? 'Invalid capability factory' : `Invalid "${operation}" capability`,
      { cause },
    )
  }
}

function installCapability(capability: RuntimeCapability, methods: Record<string, unknown>): void {
  if (Object.hasOwn(methods, capability.operation)) {
    throw new TypeError(`Duplicate "${capability.operation}" capability`)
  }
  methods[capability.operation] = async (...args: never[]) => {
    try {
      return await capability.run(...args)
    } catch (cause) {
      throw normalizePasetoError(cause)
    }
  }
}

const LocalProtocolRuntime = class LocalProtocol {
  readonly version: Version
  readonly purpose = 'local' as const

  constructor(...factories: unknown[]) {
    if (factories.length === 0) throw new TypeError('at least one capability factory is required')
    const methods: Record<string, unknown> = {}
    let version: Version | undefined
    for (const factory of factories) {
      const capability = loadCapability(factory, 'local', version)
      version ??= capability.version
      installCapability(capability, methods)
    }
    this.version = version!
    Object.assign(this, methods)
    Object.freeze(this)
  }
}

const PublicProtocolRuntime = class PublicProtocol {
  readonly version: Version
  readonly purpose = 'public' as const

  constructor(...factories: unknown[]) {
    if (factories.length === 0) throw new TypeError('at least one capability factory is required')
    const methods: Record<string, unknown> = {}
    let version: Version | undefined
    for (const factory of factories) {
      const capability = loadCapability(factory, 'public', version)
      version ??= capability.version
      installCapability(capability, methods)
    }
    this.version = version!
    Object.assign(this, methods)
    Object.freeze(this)
  }
}

/**
 * Composes selected local-purpose capabilities into a same-version protocol instance.
 *
 * @category Protocol Composition
 */
export const LocalProtocol = LocalProtocolRuntime as unknown as LocalProtocolConstructor

/**
 * Composes selected public-purpose capabilities into a same-version protocol instance.
 *
 * @category Protocol Composition
 */
export const PublicProtocol = PublicProtocolRuntime as unknown as PublicProtocolConstructor
