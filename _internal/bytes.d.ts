import { PAE } from '../index.js';
export declare const empty: Uint8Array;
export declare function checkBytes(value: unknown, name: string, length?: number): asserts value is Uint8Array;
export declare function copyBytes(value: Uint8Array): Uint8Array;
export declare function concat(...pieces: readonly Uint8Array[]): Uint8Array;
export declare function ascii(value: string): Uint8Array;
export declare function decodeUtf8(value: Uint8Array): string;
export declare function randomBytes(length: number): Uint8Array;
export declare function equalBytes(left: Uint8Array, right: Uint8Array): boolean;
export declare function toB64u(input: Uint8Array): string;
export declare function b64u(input: string): Uint8Array;
export declare function b64(input: string): Uint8Array;
export declare function decodeBase64url(input: string, name: string): Uint8Array;
export declare function uint32be(value: number): Uint8Array;
export declare function readUint32be(input: Uint8Array, offset: number): number;
export declare function positiveInteger(value: number, name: string): number;
export declare function webCryptoBytes(input: Uint8Array): Uint8Array<ArrayBuffer>;
export { PAE };
//# sourceMappingURL=bytes.d.ts.map