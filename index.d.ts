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
/**
 * Supported PASETO and PASERK protocol versions.
 *
 * @category Protocol Composition
 */
export type Version = 1 | 2 | 3 | 4;
/**
 * A value accepted in a PASETO claims object.
 *
 * @category Tokens and Claims
 */
export type JsonValue = null | boolean | number | string | readonly JsonValue[] | {
    readonly [key: string]: JsonValue;
};
/**
 * A decoded PASETO claims object.
 *
 * Registered claims are strings. `exp`, `iat`, and `nbf` use RFC 3339 date-time strings rather than
 * numeric dates. Additional string-keyed claims may contain any {@link JsonValue}.
 *
 * @category Tokens and Claims
 */
export type Claims = {
    [key: string]: JsonValue;
} & {
    /** Intended audience. */
    aud?: string;
    /** Expiration time as an RFC 3339 date-time string. */
    exp?: string;
    /** Issued-at time as an RFC 3339 date-time string. */
    iat?: string;
    /** Issuer. */
    iss?: string;
    /** Token identifier. */
    jti?: string;
    /** Not-before time as an RFC 3339 date-time string. */
    nbf?: string;
    /** Subject. */
    sub?: string;
};
type JsonCompatible<T> = T extends null | boolean | number | string ? T : T extends (...args: never[]) => unknown ? never : T extends readonly unknown[] ? {
    readonly [K in keyof T]: JsonCompatible<T[K]>;
} : T extends object ? {
    readonly [K in keyof T]: K extends string | number ? JsonCompatible<T[K]> : never;
} : never;
type CompatibleClaims<T extends object> = T extends readonly unknown[] ? never : {
    readonly [K in keyof T]: K extends 'aud' | 'exp' | 'iat' | 'iss' | 'jti' | 'nbf' | 'sub' ? T[K] extends string | undefined ? T[K] : never : K extends string | number ? JsonCompatible<T[K]> : never;
};
/**
 * An application claims object accepted for token production.
 *
 * @typeParam T - Application claims type checked for JSON-compatible values and registered claims
 */
type ClaimsInput<T extends object> = T extends Claims ? T : T & CompatibleClaims<NoInfer<T>>;
/**
 * Options controlling secret-key extractability.
 *
 * @category Keys
 */
export interface KeyOptions {
    /** Whether secret key material may later be exported or protected with PASERK. Defaults to false. */
    extractable?: boolean;
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
    footer?: Uint8Array;
    /** Current time used for generated temporal claims. */
    now?: Date;
    /** Add an `iat` claim when one is not already present. Defaults to true. */
    addIssuedAt?: boolean;
    /** Lifetime in seconds. Overrides an `exp` claim. Defaults to 3600 when `exp` is absent. */
    expiresIn?: number;
    /** Remove any `exp` claim when true; preserve normal expiration handling when false. */
    nonExpiring?: boolean;
} & ([V] extends [3 | 4] ? {
    /** Authenticated data that is not stored in the token. */
    implicitAssertion?: Uint8Array;
} : {
    /** @internal */
    implicitAssertion?: never;
});
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
    footer?: Uint8Array;
    /** Current time used for temporal claim validation. */
    now?: Date;
    /** Permitted temporal skew in seconds. Defaults to zero. */
    clockTolerance?: number;
    /** Accept a claims object without an `exp` claim. Defaults to false. */
    allowNonExpiring?: boolean;
    /** Maximum token age in seconds, measured from `iat`. */
    maxTokenAge?: number;
    /** Expected `aud` claim. Any listed value may match. */
    audience?: string | readonly string[];
    /** Expected `iss` claim. Any listed value may match. */
    issuer?: string | readonly string[];
    /** Expected `sub` claim. */
    subject?: string;
    /** Expected `jti` claim. */
    tokenIdentifier?: string;
    /** Additional claims that must be present. */
    requiredClaims?: readonly string[];
} & ([V] extends [3 | 4] ? {
    /** Authenticated data that is not stored in the token. */
    implicitAssertion?: Uint8Array;
} : {
    /** @internal */
    implicitAssertion?: never;
});
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
    claims: T;
    /** Authenticated token footer. */
    footer: Uint8Array;
}
/**
 * Parameters for an Argon2id implementation. Memory is expressed in bytes.
 *
 * @category Password-Based Key Wrapping
 */
export interface Argon2idParameters {
    /** Memory cost in bytes. */
    readonly memory: number;
    /** Number of passes over memory. */
    readonly passes: number;
    /** Degree of parallelism. */
    readonly parallelism: number;
    /** Derived-key length in bytes. */
    readonly length: number;
}
/**
 * Replaceable Argon2id implementation contract.
 *
 * @category Password-Based Key Wrapping
 */
export interface Argon2id {
    /** Type discriminator, always `KDF`. */
    readonly type: 'KDF';
    /** Argon2id implementation name. */
    readonly name: 'Argon2id' | (string & {});
    /**
     * Derives key material from a password using Argon2id.
     *
     * @param password - Password bytes
     * @param salt - Salt bytes
     * @param parameters - Argon2id parameters
     */
    Derive(password: Uint8Array, salt: Uint8Array, parameters: Readonly<Argon2idParameters>): Promise<Uint8Array>;
}
/**
 * Factory function for an Argon2id implementation.
 *
 * @category Password-Based Key Wrapping
 */
export type Argon2idFactory = () => Readonly<Argon2id>;
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
export type PasswordUnwrapOptions<V extends Version> = KeyOptions & ([V] extends [1 | 3] ? {
    /** Maximum PBKDF2 iterations accepted. Defaults to 1,000,000. */
    maxIterations?: number;
    /** @internal */
    maxMemory?: never;
    /** @internal */
    maxPasses?: never;
    /** @internal */
    maxParallelism?: never;
} : [V] extends [2 | 4] ? {
    /** @internal */
    maxIterations?: never;
    /** Maximum Argon2 memory in bytes accepted. Defaults to 1 GiB. */
    maxMemory?: number;
    /** Maximum Argon2 passes accepted. Defaults to 10. */
    maxPasses?: number;
    /** Maximum Argon2 parallelism accepted. Defaults to 16. */
    maxParallelism?: number;
} : {
    /** @internal */
    maxIterations?: never;
    /** @internal */
    maxMemory?: never;
    /** @internal */
    maxPasses?: never;
    /** @internal */
    maxParallelism?: never;
});
/**
 * Resource limits passed to a low-level password-unwrapping implementation. V1 and v3 receive
 * `maxIterations`; v2 and v4 receive `maxMemory`, `maxPasses`, and `maxParallelism`.
 *
 * The protocol adapter validates the caller's options and handles key extractability separately.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - PASERK version selecting PBKDF2 limits for v1/v3 or Argon2id limits for v2/v4
 */
export type PasswordUnwrapLimits<V extends Version> = [V] extends [1 | 3] ? {
    maxIterations?: number;
} : [V] extends [2 | 4] ? {
    maxMemory?: number;
    maxPasses?: number;
    maxParallelism?: number;
} : Record<PropertyKey, never>;
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
        readonly name: string;
    };
    /** Whether key material may be exported. */
    readonly extractable: boolean;
    /** Implementation-defined key role. */
    readonly type: 'public' | 'secret' | (string & {});
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
    crypto: {
        subtle: {
            generateKey(...args: any[]): Promise<infer R>;
        };
    };
} ? Extract<R, {
    type: string;
}> : CryptoKeyStructuralFallback;
/**
 * Used as {@link CryptoKey} when the host runtime's `crypto` global is not exposed on `typeof
 * globalThis`, including when it is absent from ambient types or declared with `const` or `let`. It
 * remains structurally compatible with host {@link !CryptoKey} declarations so values flow freely to
 * and from {@link !SubtleCrypto} APIs.
 *
 * @internal
 */
interface CryptoKeyStructuralFallback {
    readonly algorithm: {
        readonly name: string;
    };
    readonly extractable: boolean;
    readonly type: string;
    readonly usages: string[];
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
    readonly publicKey: P;
    /** Secret key. */
    readonly secretKey: S;
}
/**
 * A plaintext symmetric-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type LocalPASERK<V extends Version = Version> = `k${V}.local.${string}`;
/**
 * A plaintext public-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PublicPASERK<V extends Version = Version> = `k${V}.public.${string}`;
/**
 * A plaintext secret-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SecretPASERK<V extends Version = Version> = `k${V}.secret.${string}`;
/**
 * A local-key identifier PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type LocalIdPASERK<V extends Version = Version> = `k${V}.lid.${string}`;
/**
 * A public-key identifier PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PublicIdPASERK<V extends Version = Version> = `k${V}.pid.${string}`;
/**
 * A secret-key identifier PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SecretIdPASERK<V extends Version = Version> = `k${V}.sid.${string}`;
/**
 * A symmetrically wrapped local-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type WrappedLocalPASERK<V extends Version = Version, Prefix extends string = string> = `k${V}.local-wrap.${Prefix}.${string}`;
/**
 * A symmetrically wrapped secret-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type WrappedSecretPASERK<V extends Version = Version, Prefix extends string = string> = `k${V}.secret-wrap.${Prefix}.${string}`;
/**
 * A password-wrapped local-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PasswordWrappedLocalPASERK<V extends Version = Version> = `k${V}.local-pw.${string}`;
/**
 * A password-wrapped secret-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type PasswordWrappedSecretPASERK<V extends Version = Version> = `k${V}.secret-pw.${string}`;
/**
 * An asymmetrically sealed local-key PASERK.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SealedLocalPASERK<V extends Version = Version> = `k${V}.seal.${string}`;
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
export type PasswordWrapOptions<V extends Version> = [V] extends [1 | 3] ? {
    /** PBKDF2 iteration count. Defaults to 100,000. */
    iterations?: number;
    /** @internal */
    memory?: never;
    /** @internal */
    passes?: never;
    /** @internal */
    parallelism?: never;
} : [V] extends [2 | 4] ? {
    /** @internal */
    iterations?: never;
    /** Argon2id memory limit in bytes. Defaults to 64 MiB. */
    memory?: number;
    /** Number of Argon2id passes. Defaults to 2. */
    passes?: number;
    /** Degree of Argon2id parallelism. Defaults to 1. */
    parallelism?: number;
} : Record<PropertyKey, never>;
/**
 * Purpose discriminator carried by every capability.
 *
 * @category Protocol Composition
 */
export type Purpose = 'local' | 'public';
type OperationMethod = (...args: never[]) => unknown;
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
export interface CapabilityFactory<P extends Purpose, V extends Version, O extends string, R extends (...args: never[]) => unknown> {
    /** Creates the validated, protocol-bound operation installed by a protocol constructor. */
    (): Readonly<{
        readonly purpose: P;
        readonly version: V;
        readonly operation: O;
        readonly run: R;
    }>;
}
/**
 * A PASERK serialization accepted when deriving a local key identifier.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type LocalKeyIDInput<V extends Version = Version> = LocalPASERK<V> | WrappedLocalPASERK<V> | PasswordWrappedLocalPASERK<V> | SealedLocalPASERK<V>;
type StrictOptions<Shape, Options extends Shape> = Options & Record<Exclude<keyof Options, keyof Shape>, never>;
/**
 * Low-level local key generation implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalGenerateKeyImplementation<V extends Version, L extends Key> = Readonly<{
    readonly version: V;
    readonly run: (extractable: boolean) => Promise<L>;
}>;
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
    readonly version: V;
    readonly run: (key: L, input: Uint8Array, footer: Uint8Array, ...implicitAssertion: [V] extends [1 | 2] ? [] : [V] extends [3 | 4] ? [implicitAssertion: Uint8Array] : [implicitAssertion?: Uint8Array]) => Promise<Uint8Array>;
}>;
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
    readonly version: V;
    readonly run: (key: L, input: Uint8Array, footer: Uint8Array, ...implicitAssertion: [V] extends [1 | 2] ? [] : [V] extends [3 | 4] ? [implicitAssertion: Uint8Array] : [implicitAssertion?: Uint8Array]) => Promise<Uint8Array>;
}>;
/**
 * Low-level local key import implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalImportKeyImplementation<V extends Version, L extends Key> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.local.${string}`, extractable: boolean) => Promise<L>;
}>;
/**
 * Low-level local key export implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalExportKeyImplementation<V extends Version, L extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: L) => Promise<`k${V}.local.${string}`>;
}>;
/**
 * Low-level local key identifier implementation.
 *
 * @category Local Key Management
 * @typeParam V - Protocol version
 */
export type LocalKeyIDImplementation<V extends Version> = Readonly<{
    readonly version: V;
    readonly run: (paserk: LocalKeyIDInput<V>) => Promise<`k${V}.lid.${string}`>;
}>;
/**
 * Low-level wrapping key generation implementation for local-purpose keys.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type LocalGenerateWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
    readonly version: V;
    readonly run: (extractable: boolean) => Promise<W>;
}>;
/**
 * Low-level wrapping key import implementation for local-purpose keys.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type LocalImportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
    readonly version: V;
    readonly run: (material: Uint8Array, extractable: boolean) => Promise<W>;
}>;
/**
 * Low-level wrapping key export implementation for local-purpose keys.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type LocalExportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: W) => Promise<Uint8Array>;
}>;
/**
 * Low-level local key wrapping implementation.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type LocalWrapKeyImplementation<V extends Version, L extends Key, W extends Key, Prefix extends string = string> = Readonly<{
    readonly version: V;
    readonly run: (key: L, wrappingKey: W) => Promise<`k${V}.local-wrap.${Prefix}.${string}`>;
}>;
/**
 * Low-level local key unwrapping implementation.
 *
 * @category Local Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type LocalUnwrapKeyImplementation<V extends Version, L extends Key, W extends Key, Prefix extends string = string> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.local-wrap.${Prefix}.${string}`, wrappingKey: W, extractable: boolean) => Promise<L>;
}>;
/**
 * Low-level password-based local key wrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalWrapKeyWithPasswordImplementation<V extends Version, L extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: L, password: Uint8Array, options: PasswordWrapOptions<V>) => Promise<`k${V}.local-pw.${string}`>;
}>;
/**
 * Low-level password-based local key unwrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 */
export type LocalUnwrapKeyWithPasswordImplementation<V extends Version, L extends Key> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.local-pw.${string}`, password: Uint8Array, limits: PasswordUnwrapLimits<V>, extractable: boolean) => Promise<L>;
}>;
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
export type LocalGenerateSealingKeyPairImplementation<V extends Version, SP extends Key, SS extends Key> = Readonly<{
    readonly version: V;
    readonly run: (extractable: boolean) => Promise<KeyPair<SP, SS>>;
}>;
/**
 * Low-level sealing public key import implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SP - Sealing public key representation
 */
export type LocalImportSealingPublicKeyImplementation<V extends Version, SP extends Key> = Readonly<{
    readonly version: V;
    readonly run: (material: Uint8Array) => Promise<SP>;
}>;
/**
 * Low-level sealing secret key import implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SS - Sealing secret key representation
 */
export type LocalImportSealingSecretKeyImplementation<V extends Version, SS extends Key> = Readonly<{
    readonly version: V;
    readonly run: (material: Uint8Array, extractable: boolean) => Promise<SS>;
}>;
/**
 * Low-level sealing public key export implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SP - Sealing public key representation
 */
export type LocalExportSealingPublicKeyImplementation<V extends Version, SP extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: SP) => Promise<Uint8Array>;
}>;
/**
 * Low-level sealing secret key export implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam SS - Sealing secret key representation
 */
export type LocalExportSealingSecretKeyImplementation<V extends Version, SS extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: SS) => Promise<Uint8Array>;
}>;
/**
 * Low-level local key sealing implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam SP - Sealing public key representation
 */
export type LocalSealKeyImplementation<V extends Version, L extends Key, SP extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: L, recipient: SP) => Promise<`k${V}.seal.${string}`>;
}>;
/**
 * Low-level local key unsealing implementation.
 *
 * @category Key Sealing
 * @typeParam V - Protocol version
 * @typeParam L - Local key representation
 * @typeParam SS - Sealing secret key representation
 */
export type LocalUnsealKeyImplementation<V extends Version, L extends Key, SS extends Key> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.seal.${string}`, recipient: SS, extractable: boolean) => Promise<L>;
}>;
/**
 * A PASERK serialization accepted when deriving a secret key identifier.
 *
 * @category PASERK Serializations
 * @typeParam V - PASERK protocol version encoded by the serialization
 */
export type SecretKeyIDInput<V extends Version = Version> = SecretPASERK<V> | WrappedSecretPASERK<V> | PasswordWrappedSecretPASERK<V>;
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
export type PublicGenerateKeyPairImplementation<V extends Version, P extends Key, S extends Key> = Readonly<{
    readonly version: V;
    readonly run: (extractable: boolean) => Promise<KeyPair<P, S>>;
}>;
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
    readonly version: V;
    readonly run: (key: S, message: Uint8Array, footer: Uint8Array, ...implicitAssertion: [V] extends [1 | 2] ? [] : [V] extends [3 | 4] ? [implicitAssertion: Uint8Array] : [implicitAssertion?: Uint8Array]) => Promise<Uint8Array>;
}>;
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
    readonly version: V;
    readonly run: (key: P, message: Uint8Array, signature: Uint8Array, footer: Uint8Array, ...implicitAssertion: [V] extends [1 | 2] ? [] : [V] extends [3 | 4] ? [implicitAssertion: Uint8Array] : [implicitAssertion?: Uint8Array]) => Promise<boolean>;
}>;
/**
 * Low-level public verification key import implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 */
export type PublicImportPublicKeyImplementation<V extends Version, P extends Key> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.public.${string}`) => Promise<P>;
}>;
/**
 * Low-level public verification key export implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 */
export type PublicExportPublicKeyImplementation<V extends Version, P extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: P) => Promise<`k${V}.public.${string}`>;
}>;
/**
 * Low-level secret signing key import implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicImportSecretKeyImplementation<V extends Version, S extends Key> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.secret.${string}`, extractable: boolean) => Promise<S>;
}>;
/**
 * Low-level secret signing key export implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicExportSecretKeyImplementation<V extends Version, S extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: S) => Promise<`k${V}.secret.${string}`>;
}>;
/**
 * Low-level public key derivation implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 * @typeParam P - Public verification key representation
 * @typeParam S - Secret signing key representation
 */
export type PublicGetPublicKeyImplementation<V extends Version, P extends Key, S extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: S) => Promise<P>;
}>;
/**
 * Low-level public key identifier implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 */
export type PublicKeyIDImplementation<V extends Version> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.public.${string}`) => Promise<`k${V}.pid.${string}`>;
}>;
/**
 * Low-level secret key identifier implementation.
 *
 * @category Public Key Management
 * @typeParam V - Protocol version
 */
export type SecretKeyIDImplementation<V extends Version> = Readonly<{
    readonly version: V;
    readonly run: (paserk: SecretKeyIDInput<V>) => Promise<`k${V}.sid.${string}`>;
}>;
/**
 * Low-level wrapping key generation implementation for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type PublicGenerateWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
    readonly version: V;
    readonly run: (extractable: boolean) => Promise<W>;
}>;
/**
 * Low-level wrapping key import implementation for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type PublicImportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
    readonly version: V;
    readonly run: (material: Uint8Array, extractable: boolean) => Promise<W>;
}>;
/**
 * Low-level wrapping key export implementation for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam W - Wrapping key representation
 */
export type PublicExportWrappingKeyImplementation<V extends Version, W extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: W) => Promise<Uint8Array>;
}>;
/**
 * Low-level secret key wrapping implementation.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type PublicWrapSecretKeyImplementation<V extends Version, S extends Key, W extends Key, Prefix extends string = string> = Readonly<{
    readonly version: V;
    readonly run: (key: S, wrappingKey: W) => Promise<`k${V}.secret-wrap.${Prefix}.${string}`>;
}>;
/**
 * Low-level secret key unwrapping implementation.
 *
 * @category Public Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 * @typeParam W - Wrapping key representation
 * @typeParam Prefix - Key-wrapping protocol prefix
 */
export type PublicUnwrapSecretKeyImplementation<V extends Version, S extends Key, W extends Key, Prefix extends string = string> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.secret-wrap.${Prefix}.${string}`, wrappingKey: W, extractable: boolean) => Promise<S>;
}>;
/**
 * Low-level password-based secret key wrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicWrapSecretKeyWithPasswordImplementation<V extends Version, S extends Key> = Readonly<{
    readonly version: V;
    readonly run: (key: S, password: Uint8Array, options: PasswordWrapOptions<V>) => Promise<`k${V}.secret-pw.${string}`>;
}>;
/**
 * Low-level password-based secret key unwrapping implementation.
 *
 * @category Password-Based Key Wrapping
 * @typeParam V - Protocol version
 * @typeParam S - Secret signing key representation
 */
export type PublicUnwrapSecretKeyWithPasswordImplementation<V extends Version, S extends Key> = Readonly<{
    readonly version: V;
    readonly run: (paserk: `k${V}.secret-pw.${string}`, password: Uint8Array, limits: PasswordUnwrapLimits<V>, extractable: boolean) => Promise<S>;
}>;
/**
 * Creates a composable local key-generation capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASETO protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local key-generation implementation
 */
export declare function LocalGenerateKey<V extends Version, L extends Key>(implementation: LocalGenerateKeyImplementation<V, L>): CapabilityFactory<'local', V, 'GenerateKey', (options?: KeyOptions) => Promise<L>>;
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
export declare function LocalEncrypt<V extends Version, L extends Key>(implementation: LocalEncryptImplementation<V, L>): CapabilityFactory<'local', V, 'Encrypt', <const C extends object, const Options extends ProduceOptions<V> = ProduceOptions<V>>(key: L, claims: ClaimsInput<C>, options?: Options & Record<Exclude<keyof Options, keyof ProduceOptions<V>>, never>) => Promise<string>>;
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
export declare function LocalDecrypt<V extends Version, L extends Key>(implementation: LocalDecryptImplementation<V, L>): CapabilityFactory<'local', V, 'Decrypt', <const Options extends ConsumeOptions<V> = ConsumeOptions<V>>(key: L, token: string, options?: Options & Record<Exclude<keyof Options, keyof ConsumeOptions<V>>, never>) => Promise<TokenResult>>;
/**
 * Creates a composable local PASERK import capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local PASERK import implementation
 */
export declare function LocalImportKey<V extends Version, L extends Key>(implementation: LocalImportKeyImplementation<V, L>): CapabilityFactory<'local', V, 'ImportKey', (paserk: `k${V}.local.${string}`, options?: KeyOptions) => Promise<L>>;
/**
 * Creates a composable local PASERK export capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @param implementation - Low-level local PASERK export implementation
 */
export declare function LocalExportKey<V extends Version, L extends Key>(implementation: LocalExportKeyImplementation<V, L>): CapabilityFactory<'local', V, 'ExportKey', (key: L) => Promise<`k${V}.local.${string}`>>;
/**
 * Creates a composable local PASERK ID capability factory.
 *
 * @category Local Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @param implementation - Low-level local PASERK ID implementation
 */
export declare function LocalKeyID<V extends Version>(implementation: LocalKeyIDImplementation<V>): CapabilityFactory<'local', V, 'KeyID', (paserk: LocalKeyIDInput<V>) => Promise<`k${V}.lid.${string}`>>;
/**
 * Creates a composable local wrapping-key generation capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key generation implementation
 */
export declare function LocalGenerateWrappingKey<V extends Version, W extends Key>(implementation: LocalGenerateWrappingKeyImplementation<V, W>): CapabilityFactory<'local', V, 'GenerateWrappingKey', (options?: KeyOptions) => Promise<W>>;
/**
 * Creates a composable local wrapping-key import capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key import implementation
 */
export declare function LocalImportWrappingKey<V extends Version, W extends Key>(implementation: LocalImportWrappingKeyImplementation<V, W>): CapabilityFactory<'local', V, 'ImportWrappingKey', (material: Uint8Array, options?: KeyOptions) => Promise<W>>;
/**
 * Creates a composable local wrapping-key export capability factory.
 *
 * @category Local Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key export implementation
 */
export declare function LocalExportWrappingKey<V extends Version, W extends Key>(implementation: LocalExportWrappingKeyImplementation<V, W>): CapabilityFactory<'local', V, 'ExportWrappingKey', (key: W) => Promise<Uint8Array>>;
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
export declare function LocalWrapKey<V extends Version, L extends Key, W extends Key, Prefix extends string = string>(implementation: LocalWrapKeyImplementation<V, L, W, Prefix>): CapabilityFactory<'local', V, 'WrapKey', (key: L, wrappingKey: W) => Promise<`k${V}.local-wrap.${Prefix}.${string}`>>;
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
export declare function LocalUnwrapKey<V extends Version, L extends Key, W extends Key, Prefix extends string = string>(implementation: LocalUnwrapKeyImplementation<V, L, W, Prefix>): CapabilityFactory<'local', V, 'UnwrapKey', (paserk: `k${V}.local-wrap.${Prefix}.${string}`, wrappingKey: W, options?: KeyOptions) => Promise<L>>;
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
export declare function LocalWrapKeyWithPassword<V extends Version, L extends Key>(implementation: LocalWrapKeyWithPasswordImplementation<V, L>): CapabilityFactory<'local', V, 'WrapKeyWithPassword', <const Options extends PasswordWrapOptions<V> = PasswordWrapOptions<V>>(key: L, password: Uint8Array, options?: Options & Record<Exclude<keyof Options, keyof PasswordWrapOptions<V>>, never>) => Promise<`k${V}.local-pw.${string}`>>;
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
export declare function LocalUnwrapKeyWithPassword<V extends Version, L extends Key>(implementation: LocalUnwrapKeyWithPasswordImplementation<V, L>): CapabilityFactory<'local', V, 'UnwrapKeyWithPassword', <const Options extends PasswordUnwrapOptions<V> = PasswordUnwrapOptions<V>>(paserk: `k${V}.local-pw.${string}`, password: Uint8Array, options?: Options & Record<Exclude<keyof Options, keyof PasswordUnwrapOptions<V>>, never>) => Promise<L>>;
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
export declare function LocalGenerateSealingKeyPair<V extends Version, SP extends Key, SS extends Key>(implementation: LocalGenerateSealingKeyPairImplementation<V, SP, SS>): CapabilityFactory<'local', V, 'GenerateSealingKeyPair', (options?: KeyOptions) => Promise<KeyPair<SP, SS>>>;
/**
 * Creates a composable sealing public-key import capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SP - Sealing public key representation
 * @param implementation - Low-level sealing public-key import implementation
 */
export declare function LocalImportSealingPublicKey<V extends Version, SP extends Key>(implementation: LocalImportSealingPublicKeyImplementation<V, SP>): CapabilityFactory<'local', V, 'ImportSealingPublicKey', (material: Uint8Array) => Promise<SP>>;
/**
 * Creates a composable sealing secret-key import capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level sealing secret-key import implementation
 */
export declare function LocalImportSealingSecretKey<V extends Version, SS extends Key>(implementation: LocalImportSealingSecretKeyImplementation<V, SS>): CapabilityFactory<'local', V, 'ImportSealingSecretKey', (material: Uint8Array, options?: KeyOptions) => Promise<SS>>;
/**
 * Creates a composable sealing public-key export capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SP - Sealing public key representation
 * @param implementation - Low-level sealing public-key export implementation
 */
export declare function LocalExportSealingPublicKey<V extends Version, SP extends Key>(implementation: LocalExportSealingPublicKeyImplementation<V, SP>): CapabilityFactory<'local', V, 'ExportSealingPublicKey', (key: SP) => Promise<Uint8Array>>;
/**
 * Creates a composable sealing secret-key export capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level sealing secret-key export implementation
 */
export declare function LocalExportSealingSecretKey<V extends Version, SS extends Key>(implementation: LocalExportSealingSecretKeyImplementation<V, SS>): CapabilityFactory<'local', V, 'ExportSealingSecretKey', (key: SS) => Promise<Uint8Array>>;
/**
 * Creates a composable local key-sealing capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @typeParam SP - Sealing public key representation
 * @param implementation - Low-level local key-sealing implementation
 */
export declare function LocalSealKey<V extends Version, L extends Key, SP extends Key>(implementation: LocalSealKeyImplementation<V, L, SP>): CapabilityFactory<'local', V, 'SealKey', (key: L, recipient: SP) => Promise<`k${V}.seal.${string}`>>;
/**
 * Creates a composable local key-unsealing capability factory.
 *
 * @category Key Sealing
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam L - Local key representation
 * @typeParam SS - Sealing secret key representation
 * @param implementation - Low-level local key-unsealing implementation
 */
export declare function LocalUnsealKey<V extends Version, L extends Key, SS extends Key>(implementation: LocalUnsealKeyImplementation<V, L, SS>): CapabilityFactory<'local', V, 'UnsealKey', (paserk: `k${V}.seal.${string}`, recipient: SS, options?: KeyOptions) => Promise<L>>;
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
export declare function PublicGenerateKeyPair<V extends Version, P extends Key, S extends Key>(implementation: PublicGenerateKeyPairImplementation<V, P, S>): CapabilityFactory<'public', V, 'GenerateKeyPair', (options?: KeyOptions) => Promise<KeyPair<P, S>>>;
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
export declare function PublicSign<V extends Version, S extends Key>(implementation: PublicSignImplementation<V, S>): CapabilityFactory<'public', V, 'Sign', <const C extends object, const Options extends ProduceOptions<V> = ProduceOptions<V>>(key: S, claims: ClaimsInput<C>, options?: Options & Record<Exclude<keyof Options, keyof ProduceOptions<V>>, never>) => Promise<string>>;
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
export declare function PublicVerify<V extends Version, P extends Key>(implementation: PublicVerifyImplementation<V, P>): CapabilityFactory<'public', V, 'Verify', <const Options extends ConsumeOptions<V> = ConsumeOptions<V>>(key: P, token: string, options?: Options & Record<Exclude<keyof Options, keyof ConsumeOptions<V>>, never>) => Promise<TokenResult>>;
/**
 * Creates a composable public PASERK import capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @param implementation - Low-level public PASERK import implementation
 */
export declare function PublicImportPublicKey<V extends Version, P extends Key>(implementation: PublicImportPublicKeyImplementation<V, P>): CapabilityFactory<'public', V, 'ImportPublicKey', (paserk: `k${V}.public.${string}`) => Promise<P>>;
/**
 * Creates a composable public PASERK export capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @param implementation - Low-level public PASERK export implementation
 */
export declare function PublicExportPublicKey<V extends Version, P extends Key>(implementation: PublicExportPublicKeyImplementation<V, P>): CapabilityFactory<'public', V, 'ExportPublicKey', (key: P) => Promise<`k${V}.public.${string}`>>;
/**
 * Creates a composable secret PASERK import capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level secret PASERK import implementation
 */
export declare function PublicImportSecretKey<V extends Version, S extends Key>(implementation: PublicImportSecretKeyImplementation<V, S>): CapabilityFactory<'public', V, 'ImportSecretKey', (paserk: `k${V}.secret.${string}`, options?: KeyOptions) => Promise<S>>;
/**
 * Creates a composable secret PASERK export capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level secret PASERK export implementation
 */
export declare function PublicExportSecretKey<V extends Version, S extends Key>(implementation: PublicExportSecretKeyImplementation<V, S>): CapabilityFactory<'public', V, 'ExportSecretKey', (key: S) => Promise<`k${V}.secret.${string}`>>;
/**
 * Creates a composable public-key derivation capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam P - Public verification key representation
 * @typeParam S - Secret signing key representation
 * @param implementation - Low-level public-key derivation implementation
 */
export declare function PublicGetPublicKey<V extends Version, P extends Key, S extends Key>(implementation: PublicGetPublicKeyImplementation<V, P, S>): CapabilityFactory<'public', V, 'GetPublicKey', (key: S) => Promise<P>>;
/**
 * Creates a composable public PASERK ID capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @param implementation - Low-level public PASERK ID implementation
 */
export declare function PublicKeyID<V extends Version>(implementation: PublicKeyIDImplementation<V>): CapabilityFactory<'public', V, 'PublicKeyID', (paserk: `k${V}.public.${string}`) => Promise<`k${V}.pid.${string}`>>;
/**
 * Creates a composable secret PASERK ID capability factory.
 *
 * @category Public Key Management
 * @typeParam V - PASERK protocol version implemented by the capability
 * @param implementation - Low-level secret PASERK ID implementation
 */
export declare function SecretKeyID<V extends Version>(implementation: SecretKeyIDImplementation<V>): CapabilityFactory<'public', V, 'SecretKeyID', (paserk: SecretKeyIDInput<V>) => Promise<`k${V}.sid.${string}`>>;
/**
 * Creates a composable wrapping-key generation capability factory for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key generation implementation for public-purpose keys
 */
export declare function PublicGenerateWrappingKey<V extends Version, W extends Key>(implementation: PublicGenerateWrappingKeyImplementation<V, W>): CapabilityFactory<'public', V, 'GenerateWrappingKey', (options?: KeyOptions) => Promise<W>>;
/**
 * Creates a composable wrapping-key import capability factory for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key import implementation for public-purpose keys
 */
export declare function PublicImportWrappingKey<V extends Version, W extends Key>(implementation: PublicImportWrappingKeyImplementation<V, W>): CapabilityFactory<'public', V, 'ImportWrappingKey', (material: Uint8Array, options?: KeyOptions) => Promise<W>>;
/**
 * Creates a composable wrapping-key export capability factory for public-purpose keys.
 *
 * @category Public Key Wrapping
 * @typeParam V - PASERK protocol version implemented by the capability
 * @typeParam W - Wrapping key representation
 * @param implementation - Low-level wrapping-key export implementation for public-purpose keys
 */
export declare function PublicExportWrappingKey<V extends Version, W extends Key>(implementation: PublicExportWrappingKeyImplementation<V, W>): CapabilityFactory<'public', V, 'ExportWrappingKey', (key: W) => Promise<Uint8Array>>;
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
export declare function PublicWrapSecretKey<V extends Version, S extends Key, W extends Key, Prefix extends string = string>(implementation: PublicWrapSecretKeyImplementation<V, S, W, Prefix>): CapabilityFactory<'public', V, 'WrapSecretKey', (key: S, wrappingKey: W) => Promise<`k${V}.secret-wrap.${Prefix}.${string}`>>;
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
export declare function PublicUnwrapSecretKey<V extends Version, S extends Key, W extends Key, Prefix extends string = string>(implementation: PublicUnwrapSecretKeyImplementation<V, S, W, Prefix>): CapabilityFactory<'public', V, 'UnwrapSecretKey', (paserk: `k${V}.secret-wrap.${Prefix}.${string}`, wrappingKey: W, options?: KeyOptions) => Promise<S>>;
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
export declare function PublicWrapSecretKeyWithPassword<V extends Version, S extends Key>(implementation: PublicWrapSecretKeyWithPasswordImplementation<V, S>): CapabilityFactory<'public', V, 'WrapSecretKeyWithPassword', <const Options extends PasswordWrapOptions<V> = PasswordWrapOptions<V>>(key: S, password: Uint8Array, options?: Options & Record<Exclude<keyof Options, keyof PasswordWrapOptions<V>>, never>) => Promise<`k${V}.secret-pw.${string}`>>;
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
export declare function PublicUnwrapSecretKeyWithPassword<V extends Version, S extends Key>(implementation: PublicUnwrapSecretKeyWithPasswordImplementation<V, S>): CapabilityFactory<'public', V, 'UnwrapSecretKeyWithPassword', <const Options extends PasswordUnwrapOptions<V> = PasswordUnwrapOptions<V>>(paserk: `k${V}.secret-pw.${string}`, password: Uint8Array, options?: Options & Record<Exclude<keyof Options, keyof PasswordUnwrapOptions<V>>, never>) => Promise<S>>;
/**
 * Stable machine-readable codes used by errors produced by this module.
 *
 * @category Errors
 */
export type PasetoErrorCode = 'ERR_PASETO_INVALID_TOKEN' | 'ERR_PASERK_INVALID' | 'ERR_PASETO_INVALID_KEY' | 'ERR_PASETO_CLAIM_VALIDATION' | 'ERR_PASETO_UNSUPPORTED_ALGORITHM';
/**
 * Base class for errors produced by this module.
 *
 * @category Errors
 * @typeParam C - Stable machine-readable error code
 */
export declare class PasetoError<C extends PasetoErrorCode = PasetoErrorCode> extends Error {
    /** Stable machine-readable error code. */
    readonly code: C;
    /**
     * @param code - Stable machine-readable error code
     * @param message - Human-readable error message
     * @param options - Error construction options
     */
    constructor(code: C, message: string, options?: ErrorOptions);
}
/**
 * The token is malformed or failed authentication.
 *
 * @category Errors
 */
export declare class InvalidTokenError extends PasetoError<'ERR_PASETO_INVALID_TOKEN'> {
    /**
     * @param message - Human-readable error message
     * @param options - Error construction options
     */
    constructor(message?: string, options?: ErrorOptions);
}
/**
 * The PASERK is malformed or failed authentication.
 *
 * @category Errors
 */
export declare class InvalidPASERKError extends PasetoError<'ERR_PASERK_INVALID'> {
    /**
     * @param message - Human-readable error message
     * @param options - Error construction options
     */
    constructor(message?: string, options?: ErrorOptions);
}
/**
 * The key is malformed, unavailable for an operation, or belongs to another protocol tuple.
 *
 * @category Errors
 */
export declare class InvalidKeyError extends PasetoError<'ERR_PASETO_INVALID_KEY'> {
    /**
     * @param message - Human-readable error message
     * @param options - Error construction options
     */
    constructor(message?: string, options?: ErrorOptions);
}
/**
 * An authenticated token contains claims that fail validation.
 *
 * @category Errors
 */
export declare class ClaimValidationError extends PasetoError<'ERR_PASETO_CLAIM_VALIDATION'> {
    /** Claim whose validation failed, when applicable. */
    readonly claim?: string;
    /**
     * @param message - Human-readable error message
     * @param claim - Claim whose validation failed
     * @param options - Error construction options
     */
    constructor(message: string, claim?: string, options?: ErrorOptions);
}
/**
 * The current runtime does not provide a required cryptographic primitive.
 *
 * @category Errors
 */
export declare class UnsupportedAlgorithmError extends PasetoError<'ERR_PASETO_UNSUPPORTED_ALGORITHM'> {
    /**
     * @param message - Human-readable error message
     * @param options - Error construction options
     */
    constructor(message: string, options?: ErrorOptions);
}
/**
 * Pre-Authentication Encoding (PAE).
 *
 * @category Utilities
 * @param pieces - Byte strings to encode
 * @see https://github.com/paseto-standard/paseto-spec/blob/master/docs/01-Protocol-Versions/Common.md#pae-definition
 */
export declare function PAE(pieces: readonly Uint8Array[]): Uint8Array;
/**
 * Web Cryptography Argon2id implementation.
 *
 * A custom {@link Argon2idFactory} can be used by third-party protocol implementations in runtimes
 * without Web Cryptography.
 *
 * @category Password-Based Key Wrapping
 */
export declare const KDF_ARGON2ID: Argon2idFactory;
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
export declare function InspectFooter(token: string): Uint8Array;
/**
 * Operation names supported by local-purpose protocol composition.
 *
 * @category Protocol Composition
 */
export type LocalOperation = 'GenerateKey' | 'Encrypt' | 'Decrypt' | 'ImportKey' | 'ExportKey' | 'KeyID' | 'GenerateWrappingKey' | 'ImportWrappingKey' | 'ExportWrappingKey' | 'WrapKey' | 'UnwrapKey' | 'WrapKeyWithPassword' | 'UnwrapKeyWithPassword' | 'GenerateSealingKeyPair' | 'ImportSealingPublicKey' | 'ImportSealingSecretKey' | 'ExportSealingPublicKey' | 'ExportSealingSecretKey' | 'SealKey' | 'UnsealKey';
/**
 * Operation names supported by public-purpose protocol composition.
 *
 * @category Protocol Composition
 */
export type PublicOperation = 'GenerateKeyPair' | 'Sign' | 'Verify' | 'ImportPublicKey' | 'ExportPublicKey' | 'ImportSecretKey' | 'ExportSecretKey' | 'GetPublicKey' | 'PublicKeyID' | 'SecretKeyID' | 'GenerateWrappingKey' | 'ImportWrappingKey' | 'ExportWrappingKey' | 'WrapSecretKey' | 'UnwrapSecretKey' | 'WrapSecretKeyWithPassword' | 'UnwrapSecretKeyWithPassword';
type BivariantOperation<Arguments extends unknown[], Result> = {
    bivarianceHack(...args: Arguments): Result;
}['bivarianceHack'];
type BivariantProduceOperation<V extends Version> = {
    bivarianceHack<const C extends object, const Options extends ProduceOptions<V> = ProduceOptions<V>>(key: Key, claims: ClaimsInput<C>, options?: StrictOptions<ProduceOptions<V>, Options>): Promise<string>;
}['bivarianceHack'];
/**
 * Installed method signature for a local-purpose operation after its factory is composed.
 *
 * @typeParam V - PASETO and PASERK protocol version
 * @typeParam O - Local-purpose operation name
 */
type LocalOperationMethod<V extends Version, O extends LocalOperation> = {
    GenerateKey: BivariantOperation<[options?: KeyOptions], Promise<Key>>;
    Encrypt: BivariantProduceOperation<V>;
    Decrypt: BivariantOperation<[
        key: Key,
        token: string,
        options?: ConsumeOptions<V>
    ], Promise<TokenResult>>;
    ImportKey: BivariantOperation<[paserk: LocalPASERK<V>, options?: KeyOptions], Promise<Key>>;
    ExportKey: BivariantOperation<[key: Key], Promise<LocalPASERK<V>>>;
    KeyID: BivariantOperation<[paserk: LocalKeyIDInput<V>], Promise<LocalIdPASERK<V>>>;
    GenerateWrappingKey: BivariantOperation<[options?: KeyOptions], Promise<Key>>;
    ImportWrappingKey: BivariantOperation<[material: Uint8Array, options?: KeyOptions], Promise<Key>>;
    ExportWrappingKey: BivariantOperation<[key: Key], Promise<Uint8Array>>;
    WrapKey: BivariantOperation<[key: Key, wrappingKey: Key], Promise<WrappedLocalPASERK<V>>>;
    UnwrapKey: BivariantOperation<[
        paserk: WrappedLocalPASERK<V>,
        wrappingKey: Key,
        options?: KeyOptions
    ], Promise<Key>>;
    WrapKeyWithPassword: BivariantOperation<[
        key: Key,
        password: Uint8Array,
        options?: PasswordWrapOptions<V>
    ], Promise<PasswordWrappedLocalPASERK<V>>>;
    UnwrapKeyWithPassword: BivariantOperation<[
        paserk: PasswordWrappedLocalPASERK<V>,
        password: Uint8Array,
        options?: PasswordUnwrapOptions<V>
    ], Promise<Key>>;
    GenerateSealingKeyPair: BivariantOperation<[options?: KeyOptions], Promise<KeyPair<Key, Key>>>;
    ImportSealingPublicKey: BivariantOperation<[material: Uint8Array], Promise<Key>>;
    ImportSealingSecretKey: BivariantOperation<[
        material: Uint8Array,
        options?: KeyOptions
    ], Promise<Key>>;
    ExportSealingPublicKey: BivariantOperation<[key: Key], Promise<Uint8Array>>;
    ExportSealingSecretKey: BivariantOperation<[key: Key], Promise<Uint8Array>>;
    SealKey: BivariantOperation<[key: Key, recipient: Key], Promise<SealedLocalPASERK<V>>>;
    UnsealKey: BivariantOperation<[
        paserk: SealedLocalPASERK<V>,
        recipient: Key,
        options?: KeyOptions
    ], Promise<Key>>;
}[O];
/**
 * Installed method signature for a public-purpose operation after its factory is composed.
 *
 * @typeParam V - PASETO and PASERK protocol version
 * @typeParam O - Public-purpose operation name
 */
type PublicOperationMethod<V extends Version, O extends PublicOperation> = {
    GenerateKeyPair: BivariantOperation<[options?: KeyOptions], Promise<KeyPair<Key, Key>>>;
    Sign: BivariantProduceOperation<V>;
    Verify: BivariantOperation<[
        key: Key,
        token: string,
        options?: ConsumeOptions<V>
    ], Promise<TokenResult>>;
    ImportPublicKey: BivariantOperation<[paserk: PublicPASERK<V>], Promise<Key>>;
    ExportPublicKey: BivariantOperation<[key: Key], Promise<PublicPASERK<V>>>;
    ImportSecretKey: BivariantOperation<[paserk: SecretPASERK<V>, options?: KeyOptions], Promise<Key>>;
    ExportSecretKey: BivariantOperation<[key: Key], Promise<SecretPASERK<V>>>;
    GetPublicKey: BivariantOperation<[key: Key], Promise<Key>>;
    PublicKeyID: BivariantOperation<[paserk: PublicPASERK<V>], Promise<PublicIdPASERK<V>>>;
    SecretKeyID: BivariantOperation<[paserk: SecretKeyIDInput<V>], Promise<SecretIdPASERK<V>>>;
    GenerateWrappingKey: BivariantOperation<[options?: KeyOptions], Promise<Key>>;
    ImportWrappingKey: BivariantOperation<[material: Uint8Array, options?: KeyOptions], Promise<Key>>;
    ExportWrappingKey: BivariantOperation<[key: Key], Promise<Uint8Array>>;
    WrapSecretKey: BivariantOperation<[key: Key, wrappingKey: Key], Promise<WrappedSecretPASERK<V>>>;
    UnwrapSecretKey: BivariantOperation<[
        paserk: WrappedSecretPASERK<V>,
        wrappingKey: Key,
        options?: KeyOptions
    ], Promise<Key>>;
    WrapSecretKeyWithPassword: BivariantOperation<[
        key: Key,
        password: Uint8Array,
        options?: PasswordWrapOptions<V>
    ], Promise<PasswordWrappedSecretPASERK<V>>>;
    UnwrapSecretKeyWithPassword: BivariantOperation<[
        paserk: PasswordWrappedSecretPASERK<V>,
        password: Uint8Array,
        options?: PasswordUnwrapOptions<V>
    ], Promise<Key>>;
}[O];
type LocalCapabilityMethod<V extends Version, O extends LocalOperation> = LocalOperation extends O ? OperationMethod : LocalOperationMethod<V, O>;
type PublicCapabilityMethod<V extends Version, O extends PublicOperation> = PublicOperation extends O ? OperationMethod : PublicOperationMethod<V, O>;
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
export type LocalCapabilityFactory<V extends Version = Version, O extends LocalOperation = LocalOperation, R extends (...args: never[]) => unknown = LocalCapabilityMethod<V, O>> = CapabilityFactory<'local', V, O, R>;
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
export type PublicCapabilityFactory<V extends Version = Version, O extends PublicOperation = PublicOperation, R extends (...args: never[]) => unknown = PublicCapabilityMethod<V, O>> = CapabilityFactory<'public', V, O, R>;
/**
 * A non-empty tuple of local-purpose capability factories.
 *
 * @category Protocol Composition
 * @typeParam V - PASETO and PASERK protocol versions permitted for tuple elements
 */
export type LocalProtocolFactories<V extends Version = Version> = readonly [
    LocalCapabilityFactory<V>,
    ...LocalCapabilityFactory<V>[]
];
/**
 * A non-empty tuple of public-purpose capability factories.
 *
 * @category Protocol Composition
 * @typeParam V - PASETO and PASERK protocol versions permitted for tuple elements
 */
export type PublicProtocolFactories<V extends Version = Version> = readonly [
    PublicCapabilityFactory<V>,
    ...PublicCapabilityFactory<V>[]
];
/**
 * Extracts the literal protocol version carried by a capability factory.
 *
 * @typeParam F - Capability factory type
 */
type CapabilityVersion<F> = F extends () => Readonly<{
    readonly version: infer V extends Version;
}> ? V : never;
/**
 * Compile-time constraint requiring a factory tuple to carry one literal protocol version.
 *
 * @typeParam F - Capability factory tuple
 */
type SameVersionFactories<F extends readonly unknown[]> = F extends readonly [unknown] ? unknown : [CapabilityVersion<F[number]>] extends [never] ? never : [CapabilityVersion<F[number]>] extends [1] ? unknown : [CapabilityVersion<F[number]>] extends [2] ? unknown : [CapabilityVersion<F[number]>] extends [3] ? unknown : [CapabilityVersion<F[number]>] extends [4] ? unknown : never;
/**
 * Compile-time constraint requiring every factory in a tuple to select a different operation.
 *
 * @typeParam F - Capability factory tuple
 * @typeParam Seen - Operation names already encountered during tuple traversal
 */
type UniqueOperationFactories<F extends readonly unknown[], Seen extends PropertyKey = never> = F extends readonly [infer Head, ...infer Tail] ? Head extends () => Readonly<{
    readonly operation: infer O extends PropertyKey;
}> ? O extends Seen ? never : UniqueOperationFactories<Tail, Seen | O> : never : unknown;
/**
 * A local protocol exposing exactly the selected capabilities.
 *
 * @category Protocol Composition
 * @typeParam F - Non-empty tuple of selected local-purpose capability factories
 */
export type LocalProtocolInstance<F extends LocalProtocolFactories> = Readonly<{
    readonly version: F[number] extends () => Readonly<{
        readonly version: infer V extends Version;
    }> ? V : never;
    readonly purpose: 'local';
} & {
    [O in LocalOperation as {
        [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
            Readonly<Record<K, () => Readonly<{
                readonly purpose: 'local';
                readonly operation: O;
            }>>>
        ] ? O : never;
    }[Exclude<keyof F, keyof (readonly unknown[])>]]: {
        [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
            Readonly<Record<K, () => Readonly<{
                readonly purpose: 'local';
                readonly operation: O;
            }>>>
        ] ? Extract<ReturnType<Extract<F[K], LocalCapabilityFactory>>, Readonly<{
            readonly run: (...args: never[]) => unknown;
        }>>['run'] : never;
    }[Exclude<keyof F, keyof (readonly unknown[])>];
}>;
/**
 * A public protocol exposing exactly the selected capabilities.
 *
 * @category Protocol Composition
 * @typeParam F - Non-empty tuple of selected public-purpose capability factories
 */
export type PublicProtocolInstance<F extends PublicProtocolFactories> = Readonly<{
    readonly version: F[number] extends () => Readonly<{
        readonly version: infer V extends Version;
    }> ? V : never;
    readonly purpose: 'public';
} & {
    [O in PublicOperation as {
        [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
            Readonly<Record<K, () => Readonly<{
                readonly purpose: 'public';
                readonly operation: O;
            }>>>
        ] ? O : never;
    }[Exclude<keyof F, keyof (readonly unknown[])>]]: {
        [K in Exclude<keyof F, keyof (readonly unknown[])>]: [F] extends [
            Readonly<Record<K, () => Readonly<{
                readonly purpose: 'public';
                readonly operation: O;
            }>>>
        ] ? Extract<ReturnType<Extract<F[K], PublicCapabilityFactory>>, Readonly<{
            readonly run: (...args: never[]) => unknown;
        }>>['run'] : never;
    }[Exclude<keyof F, keyof (readonly unknown[])>];
}>;
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
    new <const F extends LocalProtocolFactories>(...factories: F & SameVersionFactories<F> & UniqueOperationFactories<F>): LocalProtocolInstance<F>;
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
    new <const F extends PublicProtocolFactories>(...factories: F & SameVersionFactories<F> & UniqueOperationFactories<F>): PublicProtocolInstance<F>;
}
/**
 * Composes selected local-purpose capabilities into a same-version protocol instance.
 *
 * @category Protocol Composition
 */
export declare const LocalProtocol: LocalProtocolConstructor;
/**
 * Composes selected public-purpose capabilities into a same-version protocol instance.
 *
 * @category Protocol Composition
 */
export declare const PublicProtocol: PublicProtocolConstructor;
export {};
//# sourceMappingURL=index.d.ts.map