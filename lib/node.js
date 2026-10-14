// Can a node choose where it sits in the DHT?
//
// A key is stored on the nodes whose ids are closest to it (XOR distance). If nodes picked
// their own ids, an attacker would start 20 nodes right next to the key you want and answer
// every lookup for it: an eclipse. So the id isn't chosen, it's derived from the address the
// others see: hash(ip:port). To land near a key you need an address that hashes near it.
//
// UDP lets anyone forge the source ip. So before a node writes anything, it must echo a token
// we sent to its ip: hmac(secret, ip). A spoofer never receives our reply, so it never has the
// token. And we store nothing per client: we just recompute the hmac and compare.

const crypto = require('node:crypto')

// The id of the node at this address. Anyone computes the same one, nobody gets to pick it.
function nodeId(host, port) {
  return crypto.createHash('sha256').update(`${host}:${port}`).digest()
}

// XOR, byte by byte. The more leading bits two ids share, the more leading
// zeros the result has, so the smaller the distance.
// d(a, a) = 0 and d(a, b) = d(b, a).
function distance(a, b) {
  const out = Buffer.alloc(32)
  for (let i = 0; i < 32; i++) {
    out[i] = a[i] ^ b[i]
  }
  return out
}

// How many leading bits two ids share: the zeros at the start of their distance.
// k bits shared means 1 in 2^k random ids gets that close.
function leadingZeros(buf) {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return i * 8 + Math.clz32(buf[i]) - 24 // clz32 counts in 32 bits, a byte is the last 8
  }
  return buf.length * 8 // all zero: the same id
}

class Tokens {
  constructor() {
    this.secret = crypto.randomBytes(32)
  }

  // Sent in our reply to host. Only we can compute it: it needs our secret.
  create(host) {
    return crypto.createHmac('sha256', this.secret).update(host).digest()
  }

  // Did whoever sends from host really receive our reply there?
  // timingSafeEqual takes the same time however many bytes match, so the token can't be
  // guessed byte by byte. It throws on a different length: garbage is just false.
  check(host, token) {
    try {
      return crypto.timingSafeEqual(this.create(host), token)
    } catch {
      return false
    }
  }
}

module.exports = { nodeId, distance, leadingZeros, Tokens }
