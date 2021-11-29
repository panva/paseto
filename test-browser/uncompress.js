function eGcd(a, b) {
  if (a <= 0n || b <= 0n) throw new RangeError('a and b MUST be > 0') // a and b MUST be positive

  let x = 0n
  let y = 1n
  let u = 1n
  let v = 0n

  while (a !== 0n) {
    const q = b / a
    const r = b % a
    const m = x - u * q
    const n = y - v * q
    b = a
    a = r
    x = u
    y = v
    u = m
    v = n
  }
  return {
    g: b,
    x: x,
    y: y,
  }
}

function modInv(a, n) {
  const egcd = eGcd(toZn(a, n), n)
  if (egcd.g !== 1n) {
    throw new RangeError(`${a.toString()} does not have inverse modulo ${n.toString()}`) // modular inverse does not exist
  } else {
    return toZn(egcd.x, n)
  }
}

function abs(a) {
  return a >= 0 ? a : -a
}

function toZn(a, n) {
  if (n <= 0n) {
    throw new RangeError('n must be > 0')
  }

  const aZn = a % n
  return aZn < 0n ? aZn + n : aZn
}

function modPow(b, e, n) {
  if (n <= 0n) {
    throw new RangeError('n must be > 0')
  } else if (n === 1n) {
    return 0n
  }

  b = toZn(b, n)

  if (e < 0n) {
    return modInv(modPow(b, abs(e), n), n)
  }

  let r = 1n
  while (e > 0) {
    if (e % 2n === 1n) {
      r = (r * b) % n
    }
    e = e / 2n
    b = b ** 2n % n
  }
  return r
}

const compressed =
  '02fbcb7c69ee1c60579be7a334134878d9c5c5bf35d552dab63c0140397ed14cef637d7720925c44699ea30e72874c72fb'

// const ec = new require(".").ec("p384");
// const expected = ec.keyFromPublic(compressed, "hex").getPublic(false, "hex");
// console.log(expected);

const two = BigInt(2)
const prime = two ** 384n - two ** 128n - two ** 96n + two ** 32n - 1n
const b =
  27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575n // ?
const pIdent = (prime + 1n) / 4n

const comp = Buffer.from(compressed, 'hex')
const signY = BigInt(comp[0] - 2)
const x = comp.subarray(1)
const xBig = BigInt(`0x${x.toString('hex')}`)

const a = xBig ** 3n - xBig * 3n + b
let yBig = modPow(a, pIdent, prime)

// "// If the parity doesn't match it's the *other* root"
if (yBig % 2n !== signY) {
  // y = prime - y
  yBig = prime - yBig
}

console.log(
  Buffer.concat([
    new Uint8Array([0x04]),
    Buffer.from(xBig.toString(16), 'hex'),
    Buffer.from(yBig.toString(16), 'hex'),
  ]).toString('hex'),
)
