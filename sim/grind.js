// How much does it cost to sit next to a key in the DHT?
//
// The id comes from hash(ip:port), so an attacker with one ip can only try its ~65k ports
// and keep the one whose id lands closest to the key. Closeness is counted in leading bits
// shared with the key: the leading zeros of the XOR distance.
//
// k bits shared means 1 in 2^k ids gets that close. With 65535 tries the best one should
// share about log2(65535) ≈ 16 bits.
//
// To be among the 20 nodes closest to a key in a network of n nodes, an id needs about
// log2(n / 20) bits. If one ip gets there, the hash makes the attack costly, not impossible.
//
//   node sim/grind.js        20 keys
//   node sim/grind.js 50     50 keys

const crypto = require('node:crypto')
const { distance, nodeId } = require('../lib/node')

// How many zero bits at the start of the buffer.
function leadingZeros(buf) {
  for (let i = 0; i < buf.length; i++) {
    const x = buf[i]
    if (x !== 0) return i * 8 + Math.clz32(x) - 24 // clz32 counts in 32 bits, a byte is the last 8
  }
  return buf.length * 8 // all zero: the same id as the key
}

// Every port of one ip: the one whose id lands closest to target.
function grind(ip, target) {
  let best = { bits: -1, port: 0 }
  for (let port = 1; port <= 65535; port++) {
    const bits = leadingZeros(distance(nodeId(ip, port), target))
    if (bits > best.bits) best = { bits, port }
  }
  return best
}

function main() {
  const keys = Number(process.argv[2]) || 20
  const results = []

  for (let i = 0; i < keys; i++) {
    const key = crypto.randomBytes(32)
    const best = grind('1.2.3.4', key)
    results.push(best.bits)
    console.log(`key ${String(i + 1).padStart(2)}  best port ${String(best.port).padStart(5)}  ${best.bits} bits`)
  }

  const mean = results.reduce((a, b) => a + b, 0) / results.length
  console.log(`\none ip, 65535 ports, ${keys} keys`)
  console.log(
    `bits shared with the key: mean ${mean.toFixed(1)}, min ${Math.min(...results)}, max ${Math.max(...results)}`,
  )

  console.log('\nbits needed to be in the 20 closest to a key:')
  for (const n of [10_000, 100_000, 1_000_000, 10_000_000]) {
    const need = Math.log2(n / 20)
    const odds = results.filter(b => b >= need).length
    console.log(
      `  ${n.toLocaleString('en').padStart(10)} nodes  ${need.toFixed(1)} bits   one ip got there for ${odds}/${keys} keys`,
    )
  }
}

main()
