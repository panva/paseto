const test = require('ava')

const { decode, errors } = require('../../lib')

test('decode input must be a string', (t) => {
  t.throws(() => decode(1), { instanceOf: TypeError, message: 'token must be a string' })
})

test('decode input must have 3 or 4 parts', (t) => {
  t.throws(() => decode('.'), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'token is not a PASETO formatted value',
  })
  t.throws(() => decode('....'), {
    instanceOf: errors.PasetoInvalid,
    code: 'ERR_PASETO_INVALID',
    message: 'token is not a PASETO formatted value',
  })
})

test('decode must be a supported header', (t) => {
  t.throws(() => decode('v0..'), {
    instanceOf: errors.PasetoNotSupported,
    code: 'ERR_PASETO_NOT_SUPPORTED',
    message: 'unsupported PASETO version',
  })
  t.throws(() => decode('v2.foo.'), {
    instanceOf: errors.PasetoNotSupported,
    code: 'ERR_PASETO_NOT_SUPPORTED',
    message: 'unsupported PASETO purpose',
  })
})

test('parses the payload', (t) => {
  t.deepEqual(
    decode(
      'v2.public.eyJpYXQiOiIyMDE5LTA3LTAyVDEyOjEwOjE1LjMxNloifWqI1SxVOBO_wrYAonuNSr84VxkOgMZf4Jn1mVUXsz9lEhxY7TdoIbgfToHIBtsrK5BUW5DD3t8ebyLz6z718gY.Zm9v',
    ),
    {
      footer: Buffer.from('foo'),
      payload: {
        iat: '2019-07-02T12:10:15.316Z',
      },
      purpose: 'public',
      version: 'v2',
    },
  )
})

test('skips parsing the payload for local tokens', (t) => {
  t.deepEqual(
    decode(
      'v2.local.eyJpYXQiOiIyMDE5LTA3LTAyVDEyOjA4OjI1LjE5OVoifS3L7e7t5YUwI1uKlW15mNNCI-aJYDDOJyEEe567xxYTcMJ4vD4MJuJiTEd1buIMQ0JoBk6kZzyknKNZKa57dg8.Zm9v',
    ),
    {
      footer: Buffer.from('foo'),
      payload: undefined,
      purpose: 'local',
      version: 'v2',
    },
  )
})
