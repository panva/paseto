import * as paseto from '.'
import {expectType} from 'tsd';

;(async () => {
  {
    const key = await paseto.V2.generateKey('public')

    paseto.V2.sign({}, key)
    paseto.V2.sign({}, key, { footer: 'foo' })
    paseto.V2.sign({}, key, { footer: Buffer.from('foo') })
    paseto.V2.sign({}, key, { footer: { foo: 'bar' } })

    const token = await paseto.V2.sign({}, key, {
      audience: 'string',
      expiresIn: '2h',
      iat: false,
      issuer: 'string',
      jti: 'string',
      kid: 'string',
      notBefore: 'string',
      now: new Date(),
      subject: 'string',
    })
    token.substring(0)

    await paseto.V2.verify(token, key)
    await paseto.V2.verify(token, key, { complete: false })

    const a = await paseto.V2.verify(token, key, { complete: true })
    if (a.footer) {
      a.footer.byteLength
    }
    a.payload
    a.purpose
    a.version

    await paseto.V2.verify(token, key, {
      audience: 'string',
      clockTolerance: '60s',
      ignoreExp: true,
      ignoreIat: true,
      ignoreNbf: true,
      issuer: 'string',
      maxTokenAge: '5m',
      now: new Date(),
      subject: 'string',
    })
  }

  {
    const key = await paseto.V1.generateKey('public')

    paseto.V1.sign({}, key)
    paseto.V1.sign({}, key, { footer: 'foo' })
    paseto.V1.sign({}, key, { footer: Buffer.from('foo') })
    paseto.V1.sign({}, key, { footer: { foo: 'bar' } })

    const token = await paseto.V1.sign({}, key, {
      audience: 'string',
      expiresIn: '2h',
      iat: false,
      issuer: 'string',
      jti: 'string',
      kid: 'string',
      notBefore: 'string',
      now: new Date(),
      subject: 'string',
    })
    token.substring(0)

    await paseto.V1.verify(token, key)
    await paseto.V1.verify(token, key, { complete: false })

    const a = await paseto.V1.verify(token, key, { complete: true })
    if (a.footer) {
      a.footer.byteLength
    }
    a.payload
    a.purpose
    a.version

    await paseto.V1.verify(token, key, {
      audience: 'string',
      clockTolerance: '60s',
      ignoreExp: true,
      ignoreIat: true,
      ignoreNbf: true,
      issuer: 'string',
      maxTokenAge: '5m',
      now: new Date(),
      subject: 'string',
    })
  }
  {
    const key = await paseto.V1.generateKey('local')

    paseto.V1.encrypt({}, key)
    paseto.V1.encrypt({}, key, { footer: 'foo' })
    paseto.V1.encrypt({}, key, { footer: Buffer.from('foo') })
    paseto.V1.encrypt({}, key, { footer: { foo: 'bar' } })

    const token = await paseto.V1.encrypt({}, key, {
      audience: 'string',
      expiresIn: '2h',
      iat: false,
      issuer: 'string',
      jti: 'string',
      kid: 'string',
      notBefore: 'string',
      now: new Date(),
      subject: 'string',
    })
    token.substring(0)

    await paseto.V1.decrypt(token, key)
    await paseto.V1.decrypt(token, key, { complete: false })

    const a = await paseto.V1.decrypt(token, key, { complete: true })
    if (a.footer) {
      a.footer.byteLength
    }
    a.payload
    a.purpose
    a.version

    const b = await paseto.V1.decrypt(token, key, {
      audience: 'string',
      clockTolerance: '60s',
      ignoreExp: true,
      ignoreIat: true,
      ignoreNbf: true,
      issuer: 'string',
      maxTokenAge: '5m',
      now: new Date(),
      subject: 'string',
    })

    switch (typeof b.arbitrary) {
      case 'symbol':
      case 'function':
      case 'bigint':
        expectType<never>(b.arbitrary)
    }

    const c = await paseto.V1.decrypt<{ foo: number }>(token, key)
    expectType<number>(c.foo)

    const d = await paseto.V1.decrypt<{ foo: number }>(token, key, { complete: true })
    expectType<number>(d.payload.foo)
  }
})()
