import * as crypto from 'crypto'
import { promisify } from 'util'

const generateKeyPair = promisify(crypto.generateKeyPair)

async function ed25519(version: number) {
  const { privateKey } = await generateKeyPair('ed25519')

  const { d, x } = privateKey.export({ format: 'jwk' })

  return {
    secret: `k${version}.secret.${Buffer.concat([
      Buffer.from(d!, 'base64'),
      Buffer.from(x!, 'base64'),
    ]).toString('base64url')}`,
    public: `k${version}.public.${x}`,
  }
}

export async function v1public() {
  const { privateKey, publicKey } = await generateKeyPair('rsa', { modulusLength: 2048 })
  return {
    secret: `k1.secret.${privateKey
      .export({ format: 'der', type: 'pkcs1' })
      .toString('base64url')}`,
    public: `k1.public.${publicKey.export({ format: 'der', type: 'pkcs1' }).toString('base64url')}`,
  }
}

export async function v2public() {
  return ed25519(2)
}

export async function v3public() {
  const { privateKey } = await generateKeyPair('ec', { namedCurve: 'P-384' })

  const { x, y, d } = privateKey.export({ format: 'jwk' })

  const yB = Buffer.from(y!, 'base64')

  return {
    secret: `k3.secret.${d}`,
    public: `k3.public.${Buffer.concat([
      Buffer.alloc(1, 0x02 + (yB[yB.byteLength - 1] & 1)),
      Buffer.from(x!, 'base64'),
    ]).toString('base64url')}`,
  }
}

export async function v4public() {
  return ed25519(4)
}
