const { sign } = require('./crypto_worker')

const pae = require('./pae')
const pack = require('./pack')

module.exports = async function signPaseto(h, m, f, alg, key, i, eo) {
  const m2 = pae(eo, h, m, f, i)
  const sig = await sign(alg, m2, key)
  return pack(h, f, m, sig)
}
