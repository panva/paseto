const verify = require('../help/verify')
const { _checkPublicKey } = require('./key')
const { post } = require('../help/consume')

const checkKey = _checkPublicKey.bind(undefined, 'v2')

module.exports = async function v2Verify(
  token,
  key,
  { complete = false, buffer = false, ...options } = {},
) {
  key = checkKey(key)

  const { m, footer } = await verify('v2.public.', token, undefined, 64, key)

  return post('v2', buffer, options, complete, m, footer, 'public')
}
