const crypto = require('crypto')

// A new identity. The public key, as base64url text, is the peer id.
function keyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519')
  return { publicKey: publicKey.export({ format: 'jwk' }).x, secretKey: privateKey } // jwk.x is the raw 32-byte key
}

// 32 random bytes. Never reuse one.
function challenge() {
  return crypto.randomBytes(32)
}

// Prove we own the secret key: sign the nonce. null: Ed25519 has its hash built in.
function respond(nonce, secretKey) {
  return crypto.sign(null, nonce, secretKey)
}

// Does this signature over this nonce come from the owner of publicKey?
// Never throws: garbage from the network is just false.
function check(nonce, signature, publicKey) {
  try {
    const key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: publicKey }, format: 'jwk' })
    return crypto.verify(null, nonce, key, signature)
  } catch {
    return false
  }
}

module.exports = { keyPair, challenge, respond, check }
