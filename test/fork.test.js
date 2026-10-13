const test = require('node:test')
const assert = require('node:assert')
const { fork } = require('../lib/fork')
const { Writer } = require('../lib/log')
const { keyPair } = require('../lib/handshake')

const daniel = keyPair()
const impostor = keyPair()

function head(keys, blocks) {
  const w = new Writer(keys)
  for (const b of blocks) w.append(b)
  return w.head()
}

// What a lying author does: sign two different logs of the same length, one for each peer.
const forPeer1 = head(daniel, ['a', 'b', 'c', 'd', 'e'])
const forPeer2 = head(daniel, ['a', 'b', 'c', 'd', 'X'])

test('should catch the author signing two logs of the same length', () => {
  assert.strictEqual(fork(daniel.publicKey, forPeer1, forPeer2), true)
  assert.strictEqual(fork(daniel.publicKey, forPeer2, forPeer1), true) // order doesn't matter
})

test('should not call the same head twice a fork', () => {
  assert.strictEqual(fork(daniel.publicKey, forPeer1, forPeer1), false)
  assert.strictEqual(fork(daniel.publicKey, forPeer1, head(daniel, ['a', 'b', 'c', 'd', 'e'])), false) // signed again, same log
})

test('should not call a log that grew a fork', () => {
  // different lengths: maybe the log just grew. That needs another check, not this one
  assert.strictEqual(fork(daniel.publicKey, head(daniel, ['a', 'b', 'c']), forPeer1), false)
})

test('should not accept an accusation built from someone else signatures', () => {
  const fake = head(impostor, ['a', 'b', 'c', 'd', 'X'])
  assert.strictEqual(fork(daniel.publicKey, forPeer1, fake), false) // one head isn't daniel's
  assert.strictEqual(fork(impostor.publicKey, forPeer1, fake), false) // nor is the other the impostor's
})

test('should not accept a head whose root was swapped after signing', () => {
  const tampered = { ...forPeer1, root: forPeer2.root } // daniel's signature, someone else's root
  assert.strictEqual(fork(daniel.publicKey, forPeer1, tampered), false)
})

test('should return false on garbage instead of throwing', () => {
  for (const [a, b] of [
    [null, forPeer2],
    [forPeer1, undefined],
    [{}, {}],
    [forPeer1, { ...forPeer2, root: 'not a buffer' }],
  ]) {
    assert.strictEqual(fork(daniel.publicKey, a, b), false)
  }
})
