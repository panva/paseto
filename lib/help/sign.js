const { sign } = require('./crypto_worker')

const pae = require('./pae')
const pack = require('./pack')
const compressPk = require('./compress_pk')

module.exports = async function signPaseto(h, m, f, alg, key, i) {
  let m2
  if (h === 'v3.public.') {
    m2 = pae(compressPk(key.key), h, m, f, i)
  } else {
    m2 = pae(h, m, f, i)
  }
  const sig = await sign(alg, m2, key)

  return pack(h, [m, sig], f)
}
