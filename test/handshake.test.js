const test = require('node:test')
const assert = require('node:assert')
const { keyPair, challenge, respond, check } = require('../lib/handshake')

const daniel = keyPair()
const impostor = keyPair()

test('should accept the real owner of the key', () => {
  const nonce = challenge()
  assert.strictEqual(check(nonce, respond(nonce, daniel.secretKey), daniel.publicKey), true)
})

test('should not accept someone signing with another key', () => {
  const nonce = challenge()
  const forged = respond(nonce, impostor.secretKey) // claims to be daniel, signs with its own key
  assert.strictEqual(check(nonce, forged, daniel.publicKey), false)
})

test('should not accept an old answer replayed for a new nonce', () => {
  const old = challenge()
  const recorded = respond(old, daniel.secretKey) // a real answer, recorded by someone listening
  const nonce = challenge()
  assert.strictEqual(check(nonce, recorded, daniel.publicKey), false)
})

test('should give a new nonce every time', () => {
  assert.strictEqual(challenge().length, 32)
  assert.notDeepStrictEqual(challenge(), challenge())
})

test('should return false on garbage instead of throwing', () => {
  const nonce = challenge()
  const sig = respond(nonce, daniel.secretKey)
  assert.strictEqual(check(nonce, sig, 'not a key'), false)
  assert.strictEqual(check(nonce, Buffer.from('short'), daniel.publicKey), false)
  assert.strictEqual(check(nonce, null, daniel.publicKey), false)
  assert.strictEqual(check(null, sig, daniel.publicKey), false)
})
