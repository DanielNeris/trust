// Did the author lie? A log has one writer, so two signed heads with the same length and
// different roots can't be an accident: the author told one thing to one peer and another
// thing to another. The pair is a proof anyone can check, with nothing but the public key.
// No vote needed, unlike a blockchain fork, where the network has to pick a side.

const { verify } = require('./handshake')
const { message } = require('./log')

const NAMESPACE = 'trust/log'

function fork(publicKey, a, b) {
  try {
    const validA = verify(NAMESPACE, message(a.length, a.root), a.signature, publicKey)
    const validB = verify(NAMESPACE, message(b.length, b.root), b.signature, publicKey)

    if (!validA || !validB) return false
    if (a.length !== b.length) return false
    if (a.root.equals(b.root)) return false

    return true
  } catch {
    return false
  }
}

module.exports = { fork }
