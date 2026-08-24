// Application code imports this from 'paseto'.
import { LocalProtocol } from '../index.ts'
// Application code imports these from 'paseto/v3/local'.
import { DecryptFactory, EncryptFactory, GenerateKeyFactory } from '../v3/local.ts'

const v3 = new LocalProtocol(GenerateKeyFactory, EncryptFactory, DecryptFactory)
const key = await v3.GenerateKey()
const token = await v3.Encrypt(key, { sub: 'alice', role: 'admin' })

const { claims } = await v3.Decrypt(key, token, { subject: 'alice', requiredClaims: ['role'] })

console.log(token)
console.log(claims)
