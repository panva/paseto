const checkAssertion = require('../help/check_assertion')
const verify = require('../help/verify')
const { _checkPublicKey } = require('./key')
const { post } = require('../help/consume')

const checkKey = _checkPublicKey.bind(undefined, 'v4')

module.exports = async function v4Verify(
  token,
  key,
  { complete = false, buffer = false, assertion, ...options } = {},
) {
  key = checkKey(key)
  const i = checkAssertion(assertion)

  const { m, footer } = await verify('v4.public.', token, undefined, 64, key, i)

  return post('v4', buffer, options, complete, m, footer, 'public')
}
