// Application code imports this from 'paseto'.
import { PublicProtocol } from '../index.ts'
// Application code imports these from 'paseto/v4/public'.
import { GenerateKeyPairFactory, SignFactory, VerifyFactory } from '../v4/public.ts'

const v4 = new PublicProtocol(GenerateKeyPairFactory, SignFactory, VerifyFactory)
const { publicKey, secretKey } = await v4.GenerateKeyPair()
const token = await v4.Sign(secretKey, { sub: 'alice', permissions: ['read', 'write'] })

const { claims } = await v4.Verify(publicKey, token, {
  subject: 'alice',
  requiredClaims: ['permissions'],
})

console.log(token)
console.log(claims)
