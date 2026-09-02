import { type CryptoKey, type LocalIdPASERK, type KeyPair, type LocalPASERK, type PasswordUnwrapLimits, type PasswordWrapOptions, type PasswordWrappedLocalPASERK, type PasswordWrappedSecretPASERK, type PublicIdPASERK, type PublicPASERK, type SealedLocalPASERK, type SecretIdPASERK, type SecretPASERK, type Version, type WrappedLocalPASERK, type WrappedSecretPASERK } from '../index.js';
import { type LocalKey, type PublicKey, type SealingPublicKey, type SealingSecretKey, type SecretKey, type WrappingKey } from './keys.js';
type LocalIdInput<V extends Version> = LocalPASERK<V> | PasswordWrappedLocalPASERK<V> | SealedLocalPASERK<V> | `k${V}.local-wrap.${string}.${string}`;
type SecretIdInput<V extends Version> = SecretPASERK<V> | PasswordWrappedSecretPASERK<V> | `k${V}.secret-wrap.${string}.${string}`;
/** Wraps a native HKDF key for a built-in v1.local or v3.local implementation. */
export declare function localKeyFromCryptoKey<V extends 1 | 3>(version: V, key: CryptoKey): LocalKey<V>;
/** Returns the native HKDF key retained by a built-in v1.local or v3.local key. */
export declare function localKeyToCryptoKey<V extends 1 | 3>(version: V, key: LocalKey<V>): CryptoKey;
/** Wraps a native RSA-PSS public key for the built-in v1.public implementation. */
export declare function publicKeyFromCryptoKeyV1(key: CryptoKey): Promise<PublicKey<1>>;
/** Wraps a native Ed25519 public key for the built-in v2.public implementation. */
export declare function publicKeyFromCryptoKeyV2(key: CryptoKey): Promise<PublicKey<2>>;
/** Wraps a native ECDSA P-384 public key for the built-in v3.public implementation. */
export declare function publicKeyFromCryptoKeyV3(key: CryptoKey): Promise<PublicKey<3>>;
/** Wraps a native Ed25519 public key for the built-in v4.public implementation. */
export declare function publicKeyFromCryptoKeyV4(key: CryptoKey): Promise<PublicKey<4>>;
/** Returns the native public key retained by a built-in public-purpose public key. */
export declare function publicKeyToCryptoKey<V extends Version>(version: V, key: PublicKey<V>): CryptoKey;
/** Wraps a native RSA-PSS private key for the built-in v1.public implementation. */
export declare function secretKeyFromCryptoKeyV1(key: CryptoKey): Promise<SecretKey<1>>;
/** Wraps a native Ed25519 private key for the built-in v2.public implementation. */
export declare function secretKeyFromCryptoKeyV2(key: CryptoKey): Promise<SecretKey<2>>;
/** Wraps a native ECDSA P-384 private key for the built-in v3.public implementation. */
export declare function secretKeyFromCryptoKeyV3(key: CryptoKey): Promise<SecretKey<3>>;
/** Wraps a native Ed25519 private key for the built-in v4.public implementation. */
export declare function secretKeyFromCryptoKeyV4(key: CryptoKey): Promise<SecretKey<4>>;
/** Returns the native private key retained by a built-in public-purpose secret key. */
export declare function secretKeyToCryptoKey<V extends Version>(version: V, key: SecretKey<V>): CryptoKey;
export declare function generateLocalKeyLegacy<V extends 1 | 3>(version: V, extractable: boolean): Promise<LocalKey<V>>;
export declare function generateLocalKeyModern<V extends 2 | 4>(version: V, extractable: boolean): Promise<LocalKey<V>>;
export declare function encryptLocalV1(key: LocalKey<1>, plaintext: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function decryptLocalV1(key: LocalKey<1>, payload: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function encryptLocalV3(key: LocalKey<3>, plaintext: Uint8Array, footer: Uint8Array, implicitAssertion: Uint8Array): Promise<Uint8Array>;
export declare function decryptLocalV3(key: LocalKey<3>, payload: Uint8Array, footer: Uint8Array, implicitAssertion: Uint8Array): Promise<Uint8Array>;
export declare function importLocalKeyLegacy<V extends 1 | 3>(version: V, paserk: LocalPASERK<V>, extractable: boolean): Promise<LocalKey<V>>;
export declare function importLocalKeyModern<V extends 2 | 4>(version: V, paserk: LocalPASERK<V>, extractable: boolean): Promise<LocalKey<V>>;
export declare function exportLocalKey<V extends Version>(version: V, key: LocalKey<V>): Promise<LocalPASERK<V>>;
export declare function localPaserkIdLegacy<V extends 1 | 3>(version: V, paserk: LocalIdInput<V>): Promise<LocalIdPASERK<V>>;
export declare function generateWrappingKey<V extends Version>(version: V, extractable: boolean): Promise<WrappingKey<V>>;
export declare function importWrappingKey<V extends Version>(version: V, material: Uint8Array, extractable: boolean): Promise<WrappingKey<V>>;
export declare function exportWrappingKey<V extends Version>(version: V, key: WrappingKey<V>): Promise<Uint8Array>;
export declare function wrapLocalKeyLegacy<V extends 1 | 3>(version: V, key: LocalKey<V>, wrapping: WrappingKey<V>): Promise<WrappedLocalPASERK<V, 'pie'>>;
export declare function unwrapLocalKeyLegacy<V extends 1 | 3>(version: V, paserk: WrappedLocalPASERK<V, 'pie'>, wrapping: WrappingKey<V>, extractable: boolean): Promise<LocalKey<V>>;
export declare function wrapLocalKeyWithPasswordLegacy<V extends 1 | 3>(version: V, key: LocalKey<V>, password: Uint8Array, options: PasswordWrapOptions<V>): Promise<PasswordWrappedLocalPASERK<V>>;
export declare function unwrapLocalKeyWithPasswordLegacy<V extends 1 | 3>(version: V, paserk: PasswordWrappedLocalPASERK<V>, password: Uint8Array, limits: PasswordUnwrapLimits<V>, extractable: boolean): Promise<LocalKey<V>>;
export declare function generateSealingKeyPairV3(extractable: boolean): Promise<KeyPair<SealingPublicKey<3>, SealingSecretKey<3>>>;
export declare function importSealingPublicKeyV3(material: Uint8Array): Promise<SealingPublicKey<3>>;
export declare function importSealingSecretKeyV3(material: Uint8Array, extractable: boolean): Promise<SealingSecretKey<3>>;
export declare function exportSealingPublicKeyV3(key: SealingPublicKey<3>): Promise<Uint8Array>;
export declare function exportSealingSecretKeyV3(key: SealingSecretKey<3>): Promise<Uint8Array>;
export declare function sealLocalKeyV3(key: LocalKey<3>, recipient: SealingPublicKey<3>): Promise<SealedLocalPASERK<3>>;
export declare function unsealLocalKeyV3(paserk: SealedLocalPASERK<3>, recipient: SealingSecretKey<3>, extractable: boolean): Promise<LocalKey<3>>;
export declare function generatePublicKeyPairV1(extractable: boolean): Promise<KeyPair<PublicKey<1>, SecretKey<1>>>;
export declare function generatePublicKeyPairV2(extractable: boolean): Promise<KeyPair<PublicKey<2>, SecretKey<2>>>;
export declare function generatePublicKeyPairV3(extractable: boolean): Promise<KeyPair<PublicKey<3>, SecretKey<3>>>;
export declare function generatePublicKeyPairV4(extractable: boolean): Promise<KeyPair<PublicKey<4>, SecretKey<4>>>;
export declare function signPublicV1(key: SecretKey<1>, message: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function verifyPublicV1(key: PublicKey<1>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array): Promise<boolean>;
export declare function signPublicV2(key: SecretKey<2>, message: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function verifyPublicV2(key: PublicKey<2>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array): Promise<boolean>;
export declare function signPublicV3(key: SecretKey<3>, message: Uint8Array, footer: Uint8Array, implicitAssertion: Uint8Array): Promise<Uint8Array>;
export declare function verifyPublicV3(key: PublicKey<3>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array, implicitAssertion: Uint8Array): Promise<boolean>;
export declare function signPublicV4(key: SecretKey<4>, message: Uint8Array, footer: Uint8Array, implicitAssertion: Uint8Array): Promise<Uint8Array>;
export declare function verifyPublicV4(key: PublicKey<4>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array, implicitAssertion: Uint8Array): Promise<boolean>;
export declare function importPublicKeyV1(paserk: PublicPASERK<1>): Promise<PublicKey<1>>;
export declare function importPublicKeyV2(paserk: PublicPASERK<2>): Promise<PublicKey<2>>;
export declare function importPublicKeyV3(paserk: PublicPASERK<3>): Promise<PublicKey<3>>;
export declare function importPublicKeyV4(paserk: PublicPASERK<4>): Promise<PublicKey<4>>;
export declare function exportPublicKey<V extends Version>(version: V, key: PublicKey<V>): Promise<PublicPASERK<V>>;
export declare function importSecretKeyV1(paserk: SecretPASERK<1>, extractable: boolean): Promise<SecretKey<1>>;
export declare function importSecretKeyV2(paserk: SecretPASERK<2>, extractable: boolean): Promise<SecretKey<2>>;
export declare function importSecretKeyV3(paserk: SecretPASERK<3>, extractable: boolean): Promise<SecretKey<3>>;
export declare function importSecretKeyV4(paserk: SecretPASERK<4>, extractable: boolean): Promise<SecretKey<4>>;
export declare function exportSecretKey<V extends Version>(version: V, key: SecretKey<V>): Promise<SecretPASERK<V>>;
export declare function getPublicKey<V extends Version>(version: V, key: SecretKey<V>): Promise<PublicKey<V>>;
export declare function publicPaserkIdLegacy<V extends 1 | 3>(version: V, paserk: PublicPASERK<V>): Promise<PublicIdPASERK<V>>;
export declare function secretPaserkIdLegacy<V extends 1 | 3>(version: V, paserk: SecretIdInput<V>): Promise<SecretIdPASERK<V>>;
export declare function wrapSecretKeyLegacy<V extends 1 | 3>(version: V, key: SecretKey<V>, wrapping: WrappingKey<V>): Promise<WrappedSecretPASERK<V, 'pie'>>;
export declare function unwrapSecretKeyLegacy<V extends 1 | 3>(version: V, paserk: WrappedSecretPASERK<V, 'pie'>, wrapping: WrappingKey<V>, extractable: boolean): Promise<SecretKey<V>>;
export declare function wrapSecretKeyWithPasswordLegacy<V extends 1 | 3>(version: V, key: SecretKey<V>, password: Uint8Array, options: PasswordWrapOptions<V>): Promise<PasswordWrappedSecretPASERK<V>>;
export declare function unwrapSecretKeyWithPasswordLegacy<V extends 1 | 3>(version: V, paserk: PasswordWrappedSecretPASERK<V>, password: Uint8Array, limits: PasswordUnwrapLimits<V>, extractable: boolean): Promise<SecretKey<V>>;
export {};
//# sourceMappingURL=operations.d.ts.map