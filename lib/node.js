const crypto = require('node:crypto')

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

class Tokens {
  constructor() {
    this.secret = crypto.randomBytes(32)
  }

  create(host) {
    return crypto.createHmac('sha256', this.secret).update(host).digest()
  }

  check(host, token) {
    try {
      return crypto.timingSafeEqual(this.create(host), token)
    } catch {
      return false
    }
  }
}

module.exports = { nodeId, distance, Tokens }
