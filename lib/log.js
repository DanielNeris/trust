// A log anyone can serve and nobody can fake.
//
// The author appends blocks and signs the head: how many blocks there are and the Merkle
// root over all of them. Anyone with a copy can then hand out a block, and the reader checks
// it without trusting whoever sent it:
//
//   1. the head's signature matches the author's public key    the author wrote this
//   2. index < length                                          the block exists at that length
//   3. the proof takes the block up to the signed root         it's that block, unchanged
//
// The length is signed with the root. The root alone doesn't say how many blocks there are,
// and two signed heads with the same length and different roots will be proof of a fork.

const { root, proof, verify } = require('./merkle')
const handshake = require('./handshake')

const NAMESPACE = 'trust/log'

// What the author signs: length (8 bytes) + root. Built in one place so the writer and
// every reader always sign and check the exact same bytes.
function message(length, root) {
  const len = Buffer.alloc(8)
  len.writeBigUInt64BE(BigInt(length))
  return Buffer.concat([len, root])
}

class Writer {
  constructor(keys) {
    this.keys = keys
    this.blocks = [] // starts empty: append() is the only way in
  }

  append(block) {
    this.blocks.push(block)
  }

  // The signed head. An empty log has no root, so nothing to sign yet.
  head() {
    const r = root(this.blocks)
    if (r === null) return null
    const length = this.blocks.length
    return { length, root: r, signature: handshake.sign(NAMESPACE, message(length, r), this.keys.secretKey) }
  }

  // Everything a peer would send for one block: the block, its proof and the signed head.
  get(index) {
    if (index < 0 || index >= this.blocks.length) return null
    return { block: this.blocks[index], index, proof: proof(this.blocks, index), head: this.head() }
  }
}

// Should I accept this block from a stranger? Only the author's key is trusted, never the sender.
// Never throws: a reply from the network can be garbage.
function accept(publicKey, reply) {
  try {
    const { head } = reply
    if (!handshake.verify(NAMESPACE, message(head.length, head.root), head.signature, publicKey)) return false
    if (!Number.isInteger(reply.index) || reply.index < 0 || reply.index >= head.length) return false
    return verify(reply.block, reply.proof, head.root)
  } catch {
    return false
  }
}

module.exports = { Writer, accept, message }
