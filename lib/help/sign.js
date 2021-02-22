const { sign } = require('./crypto_worker')

const pae = require('./pae')
const pack = require('./pack')

module.exports = async function signPaseto (h, m, f, alg, key, expectedSigLength) {
  const m2 = pae(h, m, f)
  const sig = await sign(alg, m2, key)

  if (sig.length !== expectedSigLength) {
    throw new TypeError(`invalid ${h.slice(0, -1)} signing key bit length`)
  }

  return pack(h, [m, sig], f)
}
