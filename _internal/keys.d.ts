import { type CryptoKey, type Key, type Version } from '../index.js';
export interface LocalKey<V extends Version = Version> extends Key {
    readonly algorithm: {
        readonly name: `PASETO v${V}.local`;
    };
    readonly type: 'secret';
    readonly version: V;
    readonly kind: 'local';
}
export interface PublicKey<V extends Version = Version> extends Key {
    readonly algorithm: {
        readonly name: `PASETO v${V}.public`;
    };
    readonly type: 'public';
    readonly version: V;
    readonly kind: 'public';
}
export interface SecretKey<V extends Version = Version> extends Key {
    readonly algorithm: {
        readonly name: `PASETO v${V}.public`;
    };
    readonly type: 'secret';
    readonly version: V;
    readonly kind: 'secret';
}
export interface WrappingKey<V extends Version = Version> extends Key {
    readonly algorithm: {
        readonly name: `PASERK k${V}.wrap`;
    };
    readonly type: 'secret';
    readonly version: V;
    readonly kind: 'wrapping';
}
export interface SealingPublicKey<V extends Version = Version> extends Key {
    readonly algorithm: {
        readonly name: `PASERK k${V}.seal`;
    };
    readonly extractable: true;
    readonly type: 'public';
    readonly version: V;
    readonly kind: 'sealing-public';
}
export interface SealingSecretKey<V extends Version = Version> extends Key {
    readonly algorithm: {
        readonly name: `PASERK k${V}.seal`;
    };
    readonly type: 'secret';
    readonly version: V;
    readonly kind: 'sealing-secret';
}
export interface KeyData<V extends Version> {
    version: V;
    material: Uint8Array;
    extractable: boolean;
}
export interface LocalKeyData<V extends Version> {
    version: V;
    material: Uint8Array | undefined;
    cryptoKey: CryptoKey | undefined;
    extractable: boolean;
}
export interface PublicKeyData<V extends Version> {
    version: V;
    material: Uint8Array | undefined;
    cryptoKey: CryptoKey;
    extractable: boolean;
}
export interface SecretKeyData<V extends Version> {
    version: V;
    material: Uint8Array | undefined;
    cryptoKey: CryptoKey;
    publicCryptoKey: CryptoKey;
    publicMaterial: Uint8Array | undefined;
    rawPublicMaterial?: Uint8Array | undefined;
    extractable: boolean;
}
export interface SealingSecretKeyData<V extends Version> extends KeyData<V> {
    publicMaterial: Uint8Array;
}
export declare class LocalKeyImpl<V extends Version> implements LocalKey<V> {
    #private;
    readonly algorithm: {
        readonly name: `PASETO v${V}.local`;
    };
    readonly type: "secret";
    readonly kind: "local";
    readonly version: V;
    readonly extractable: boolean;
    constructor(version: V, material: Uint8Array | undefined, extractable: boolean, cryptoKey?: CryptoKey);
}
export declare class PublicKeyImpl<V extends Version> implements PublicKey<V> {
    #private;
    readonly algorithm: {
        readonly name: `PASETO v${V}.public`;
    };
    readonly type: "public";
    readonly kind: "public";
    readonly version: V;
    readonly extractable: boolean;
    constructor(version: V, material: Uint8Array | undefined, cryptoKey: CryptoKey);
}
export declare class SecretKeyImpl<V extends Version> implements SecretKey<V> {
    #private;
    readonly algorithm: {
        readonly name: `PASETO v${V}.public`;
    };
    readonly type: "secret";
    readonly kind: "secret";
    readonly version: V;
    readonly extractable: boolean;
    constructor(version: V, cryptoKey: CryptoKey, material: Uint8Array | undefined, publicMaterial: Uint8Array, rawPublicMaterial: Uint8Array | undefined, publicCryptoKey: CryptoKey);
}
export declare class WrappingKeyImpl<V extends Version> implements WrappingKey<V> {
    #private;
    readonly algorithm: {
        readonly name: `PASERK k${V}.wrap`;
    };
    readonly type: "secret";
    readonly kind: "wrapping";
    readonly version: V;
    readonly extractable: boolean;
    constructor(version: V, material: Uint8Array, extractable: boolean);
}
export declare class SealingPublicKeyImpl<V extends Version> implements SealingPublicKey<V> {
    #private;
    readonly algorithm: {
        readonly name: `PASERK k${V}.seal`;
    };
    readonly type: "public";
    readonly kind: "sealing-public";
    readonly version: V;
    readonly extractable = true;
    constructor(version: V, material: Uint8Array);
}
export declare class SealingSecretKeyImpl<V extends Version> implements SealingSecretKey<V> {
    #private;
    readonly algorithm: {
        readonly name: `PASERK k${V}.seal`;
    };
    readonly type: "secret";
    readonly kind: "sealing-secret";
    readonly version: V;
    readonly extractable: boolean;
    constructor(version: V, material: Uint8Array, publicMaterial: Uint8Array, extractable: boolean);
}
export declare function localKeyData<V extends Version>(key: object, version: V, name?: string): LocalKeyData<V>;
export declare function publicKeyData<V extends Version>(key: object, version: V, name?: string): PublicKeyData<V>;
export declare function secretKeyData<V extends Version>(key: object, version: V): SecretKeyData<V>;
export declare function wrappingKeyData<V extends Version>(key: object, version: V, name?: string): KeyData<V>;
export declare function sealingPublicKeyData<V extends Version>(key: object, version: V, name?: string): KeyData<V>;
export declare function sealingSecretKeyData<V extends Version>(key: object, version: V): SealingSecretKeyData<V>;
export declare function requireExtractable(data: {
    readonly extractable: boolean;
}): void;
//# sourceMappingURL=keys.d.ts.map