// Did the author lie? A log has one writer, so two signed heads with the same length and
// different roots can't be an accident: the author told one thing to one peer and another
// thing to another. The pair is a proof anyone can check, with nothing but the public key.
// No vote needed, unlike a blockchain fork, where the network has to pick a side.
//
// The other way to lie is to rewrite the past while the log grows: sign 3 blocks, then sign
// 5 blocks whose first 3 are different. rewrote() checks it with the newer blocks: they must
// hash to the newer root, and their beginning must not hash to the older root.

const { verify } = require('./handshake')
const { message } = require('./log')
const { root } = require('./merkle')

const NAMESPACE = 'trust/log'

// Did the author sign this head? Only then can it count against them.
function signed(publicKey, head) {
  return verify(NAMESPACE, message(head.length, head.root), head.signature, publicKey)
}

// Two heads, same length, different roots, both signed by the author. Never throws.
function fork(publicKey, a, b) {
  try {
    if (!signed(publicKey, a) || !signed(publicKey, b)) return false // an accusation needs the author's signatures
    if (a.length !== b.length) return false // different lengths: maybe it just grew, see rewrote()
    if (a.root.equals(b.root)) return false // the same log, signed twice

    return true
  } catch {
    return false
  }
}

// A longer head whose beginning is not the older head. Never throws.
function rewrote(publicKey, older, newer, blocks) {
  try {
    if (!signed(publicKey, older) || !signed(publicKey, newer)) return false
    if (older.length >= newer.length) return false // the older head must be shorter: same length is fork()
    if (!root(blocks).equals(newer.root)) return false // these must be the blocks the author signed, not invented ones

    return !root(blocks.slice(0, older.length)).equals(older.root) // the beginning changed
  } catch {
    return false
  }
}

module.exports = { fork, rewrote }
