import { type CryptoKey } from '../index.js';
import { type PublicKey, type PublicKeyData, type SealingSecretKeyData, type SecretKey, type SecretKeyData } from './keys.js';
export declare function webCryptoOperation<T>(algorithm: string, operation: () => Promise<T>): Promise<T>;
export declare function digest(name: 'SHA-384', input: Uint8Array): Promise<Uint8Array>;
export declare function hmacSha384(key: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
/** Validates a CryptoKey accepted by the built-in v1.local and v3.local implementations. */
export declare function assertLocalCryptoKey(key: CryptoKey): void;
/** Imports PASETO local key material as the native derivation key used by v1.local and v3.local. */
export declare function importLocalCryptoKey(material: Uint8Array): Promise<CryptoKey>;
export declare function hkdfSha384(key: Uint8Array | CryptoKey, info: Uint8Array, length: number, salt?: Uint8Array): Promise<Uint8Array>;
export declare function pbkdf2Sha384(password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Promise<Uint8Array>;
export declare function aesCtr(operation: 'encrypt' | 'decrypt', key: Uint8Array, counter: Uint8Array, input: Uint8Array): Promise<Uint8Array>;
export declare function pemToDer(input: string): Uint8Array;
export declare function decompressP384(compressed: Uint8Array): Uint8Array;
export declare function compressP384(raw: Uint8Array): Uint8Array;
export declare function jwkBytes(value: string | undefined, name: string): Uint8Array;
/** Wraps a native RSA-PSS public key for use with the built-in v1.public implementation. */
export declare function importRsaPublicCryptoKey(key: CryptoKey): Promise<PublicKey<1>>;
/** Wraps a native Ed25519 public key for a built-in public-purpose implementation. */
export declare function importEd25519PublicCryptoKey<V extends 2 | 4>(version: V, key: CryptoKey): Promise<PublicKey<V>>;
/** Wraps a native ECDSA P-384 public key for the built-in v3.public implementation. */
export declare function importP384PublicCryptoKey(key: CryptoKey): Promise<PublicKey<3>>;
/** Wraps a native RSA-PSS private key for use with the built-in v1.public implementation. */
export declare function importRsaSecretCryptoKey(key: CryptoKey): Promise<SecretKey<1>>;
/** Wraps a native Ed25519 private key for a built-in public-purpose implementation. */
export declare function importEd25519SecretCryptoKey<V extends 2 | 4>(version: V, key: CryptoKey): Promise<SecretKey<V>>;
/** Wraps a native ECDSA P-384 private key for the built-in v3.public implementation. */
export declare function importP384SecretCryptoKey(key: CryptoKey): Promise<SecretKey<3>>;
export declare function importRsaSecretKey(material: Uint8Array, extractable: boolean): Promise<SecretKey<1>>;
export declare function generateRsaKeyPair(extractable: boolean): Promise<{
    secretKey: SecretKey<1>;
    publicKey: PublicKey<1>;
}>;
export declare function p384RawPublicFromSecret(material: Uint8Array, algorithm: 'ECDSA' | 'ECDH', usage: 'sign' | 'deriveBits'): Promise<Uint8Array>;
export declare function importP384SecretKey(material: Uint8Array, extractable: boolean): Promise<SecretKey<3>>;
export declare function importEd25519SecretKey<V extends 2 | 4>(version: V, material: Uint8Array, extractable: boolean): Promise<SecretKey<V>>;
export declare function generateP384KeyPair(extractable: boolean): Promise<{
    secretKey: SecretKey<3>;
    publicKey: PublicKey<3>;
}>;
export declare function generateEd25519KeyPair<V extends 2 | 4>(version: V, extractable: boolean): Promise<{
    secretKey: SecretKey<V>;
    publicKey: PublicKey<V>;
}>;
export declare function importRsaPublicKey(material: Uint8Array): Promise<PublicKey<1>>;
export declare function p384PublicCryptoKey(material: Uint8Array, algorithm: 'ECDSA' | 'ECDH', usages: KeyUsage[], extractable?: boolean): Promise<CryptoKey>;
export declare function p384PrivateCryptoKey(data: SecretKeyData<3> | SealingSecretKeyData<3>, algorithm: 'ECDSA' | 'ECDH', usage: 'sign' | 'deriveBits'): Promise<CryptoKey>;
export declare function importP384PublicKey(material: Uint8Array): Promise<PublicKey<3>>;
export declare function importEd25519PublicKey<V extends 2 | 4>(version: V, material: Uint8Array): Promise<PublicKey<V>>;
export declare function encryptV1Local(key: Uint8Array | CryptoKey, message: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function encryptV3Local(key: Uint8Array | CryptoKey, message: Uint8Array, footer: Uint8Array, implicit: Uint8Array): Promise<Uint8Array>;
export declare function decryptV1Local(key: Uint8Array | CryptoKey, payload: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function decryptV3Local(key: Uint8Array | CryptoKey, payload: Uint8Array, footer: Uint8Array, implicit: Uint8Array): Promise<Uint8Array>;
export declare function signV1Public(data: SecretKeyData<1>, message: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function verifyV1Public(data: PublicKeyData<1>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array): Promise<boolean>;
export declare function signV3Public(data: SecretKeyData<3>, message: Uint8Array, footer: Uint8Array, implicit: Uint8Array): Promise<Uint8Array>;
export declare function verifyV3Public(data: PublicKeyData<3>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array, implicit: Uint8Array): Promise<boolean>;
export declare function signV2Public(data: SecretKeyData<2>, message: Uint8Array, footer: Uint8Array): Promise<Uint8Array>;
export declare function verifyV2Public(data: PublicKeyData<2>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array): Promise<boolean>;
export declare function signV4Public(data: SecretKeyData<4>, message: Uint8Array, footer: Uint8Array, implicit: Uint8Array): Promise<Uint8Array>;
export declare function verifyV4Public(data: PublicKeyData<4>, message: Uint8Array, signature: Uint8Array, footer: Uint8Array, implicit: Uint8Array): Promise<boolean>;
//# sourceMappingURL=crypto.d.ts.map