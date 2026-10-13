// Is this peer really who it says it is?
//
// A peer connects and claims "I am public key X". Anyone can claim that: a public key is
// public. What only the real owner has is the secret key, so we ask for proof:
//
//   1. we send a nonce: 32 random bytes, new every time
//   2. they sign it with their secret key and send the signature back
//   3. we verify the signature with X
//
// Why a new nonce every time: if we always asked them to sign the same thing, an impostor
// could record one real answer and replay it forever. A fresh nonce makes old answers useless.
//
// Every signature starts with a namespace ('trust/handshake', 'trust/log'). The nonce is
// chosen by someone else and has the same size as a Merkle root. Without the namespace, an
// attacker could send a fake root as the "nonce" and walk away with a valid signed root.
// With it, a signature made for one purpose never verifies for another.

const crypto = require('node:crypto')

// A new identity. The public key, as base64url text, is the peer id.
function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  return { publicKey: publicKey.export({ format: 'jwk' }).x, secretKey: privateKey } // jwk.x is the raw 32-byte key
}

// Sign data under a namespace. null: Ed25519 has its hash built in.
function sign(namespace, data, secretKey) {
  return crypto.sign(null, Buffer.concat([Buffer.from(namespace), data]), secretKey)
}

// Was data signed under this namespace by the owner of publicKey?
// Never throws: garbage from the network is just false.
function verify(namespace, data, signature, publicKey) {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' })
    return crypto.verify(null, Buffer.concat([Buffer.from(namespace), data]), key, signature)
  } catch {
    return false
  }
}

// 32 random bytes. Never reuse one.
function challenge() {
  return crypto.randomBytes(32)
}

// Prove we own the secret key: sign the nonce.
function respond(nonce, secretKey) {
  return sign('trust/handshake', nonce, secretKey)
}

// Does this signature over this nonce come from the owner of publicKey?
function check(nonce, signature, publicKey) {
  return verify('trust/handshake', nonce, signature, publicKey)
}

module.exports = { keyPair, sign, verify, challenge, respond, check }
