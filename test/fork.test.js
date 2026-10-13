const test = require('node:test')
const assert = require('node:assert')
const { fork, rewrote } = require('../lib/fork')
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

function log(keys, blocks) {
  return { head: head(keys, blocks), blocks }
}

const before = log(daniel, ['a', 'b', 'c'])
const grew = log(daniel, ['a', 'b', 'c', 'd', 'e'])
const rewritten = log(daniel, ['a', 'X', 'c', 'd', 'e']) // block 1 changed, then two more added

test('should catch the author rewriting the past while the log grows', () => {
  assert.strictEqual(rewrote(daniel.publicKey, before.head, rewritten.head, rewritten.blocks), true)
})

test('should not call a log that only grew a rewrite', () => {
  assert.strictEqual(rewrote(daniel.publicKey, before.head, grew.head, grew.blocks), false)
})

test('should not take blocks that are not the ones the new head signed', () => {
  // the honest new head, but invented blocks: anyone could "prove" a rewrite this way
  assert.strictEqual(rewrote(daniel.publicKey, before.head, grew.head, rewritten.blocks), false)
})

test('should only compare an older head with a longer one', () => {
  assert.strictEqual(rewrote(daniel.publicKey, rewritten.head, before.head, before.blocks), false) // backwards
  assert.strictEqual(rewrote(daniel.publicKey, grew.head, rewritten.head, rewritten.blocks), false) // same length: that's fork()
})

test('should not accept a rewrite built from someone else signatures', () => {
  const fake = log(impostor, ['a', 'X', 'c', 'd', 'e'])
  assert.strictEqual(rewrote(daniel.publicKey, before.head, fake.head, fake.blocks), false)
  assert.strictEqual(
    rewrote(daniel.publicKey, log(impostor, ['a', 'b', 'c']).head, rewritten.head, rewritten.blocks),
    false,
  )
})

test('should return false on garbage instead of throwing in rewrote', () => {
  for (const args of [
    [null, rewritten.head, rewritten.blocks],
    [before.head, undefined, rewritten.blocks],
    [before.head, rewritten.head, null],
    [before.head, rewritten.head, []],
  ]) {
    assert.strictEqual(rewrote(daniel.publicKey, ...args), false)
  }
})
