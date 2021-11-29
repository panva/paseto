import * as base64url from './base64url.js'
import * as stable from '../../stablelib/ed25519.js'
import random from './random.js'

function ed25519(version: number) {
  const { publicKey, secretKey } = stable.generateKeyPairFromSeed(random(new Uint8Array(32)))

  return {
    secret: `k${version}.secret.${base64url.encode(secretKey)}`,
    public: `k${version}.public.${base64url.encode(publicKey)}`,
  }
}

export async function v1public() {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: 'SHA-384' },
    },
    true,
    ['sign', 'verify'],
  )

  return {
    secret: `k1.secret.${base64url.encode(
      new Uint8Array(await crypto.subtle.exportKey('pkcs8', <CryptoKey>privateKey)).slice(26),
    )}`,
    public: `k1.public.${base64url.encode(
      new Uint8Array(await crypto.subtle.exportKey('spki', <CryptoKey>publicKey)).slice(24),
    )}`,
  }
}

export async function v2public() {
  return ed25519(2)
}

export async function v3public() {
  const { privateKey } = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-384' },
    true,
    ['sign', 'verify'],
  )

  const { x, y, d } = await crypto.subtle.exportKey('jwk', <CryptoKey>privateKey)

  const yB = base64url.decode(y!)

  return {
    secret: `k3.secret.${d}`,
    public: `k3.public.${base64url.encode(
      new Uint8Array([0x02 + (yB[yB.byteLength - 1] & 1), ...base64url.decode(x!)]),
    )}`,
  }
}

export async function v4public() {
  return ed25519(4)
}
