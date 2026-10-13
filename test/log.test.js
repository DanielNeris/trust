const test = require('node:test')
const assert = require('node:assert')
const { Writer, accept, message } = require('../lib/log')
const { keyPair, respond } = require('../lib/handshake')

const daniel = keyPair()
const impostor = keyPair()

function writer(keys, blocks) {
  const w = new Writer(keys)
  for (const b of blocks) w.append(b)
  return w
}

const log = writer(daniel, ['a', 'b', 'c', 'd', 'e'])

test('should have no head and no blocks while empty', () => {
  const w = new Writer(daniel)
  assert.strictEqual(w.head(), null)
  assert.strictEqual(w.get(0), null)
})

test('should accept every block of the log, whoever sends it', () => {
  for (let i = 0; i < 5; i++) assert.strictEqual(accept(daniel.publicKey, log.get(i)), true, `block ${i}`)
})

test('should not accept a block changed by the peer that sent it', () => {
  assert.strictEqual(accept(daniel.publicKey, { ...log.get(2), block: 'x' }), false)
})

test('should not accept a log signed by someone else', () => {
  const fake = writer(impostor, ['a', 'b', 'c', 'd', 'x'])
  assert.strictEqual(accept(daniel.publicKey, fake.get(4)), false)
})

test('should not accept a head with its length or root changed', () => {
  const reply = log.get(2)
  assert.strictEqual(accept(daniel.publicKey, { ...reply, head: { ...reply.head, length: 6 } }), false)
  const other = writer(daniel, ['a', 'b', 'c']).head()
  assert.strictEqual(accept(daniel.publicKey, { ...reply, head: { ...reply.head, root: other.root } }), false)
})

test('should not accept an index outside the signed length', () => {
  const reply = log.get(4)
  assert.strictEqual(accept(daniel.publicKey, { ...reply, index: 5 }), false)
  assert.strictEqual(accept(daniel.publicKey, { ...reply, index: -1 }), false)
  assert.strictEqual(accept(daniel.publicKey, { ...reply, index: 1.5 }), false)
})

test('should not take a handshake answer as a signed head', () => {
  // the attack: send the author a fake root as a handshake "nonce", then present its answer as a head
  const fake = writer(impostor, ['evil'])
  const head = fake.head()
  const tricked = respond(message(head.length, head.root), daniel.secretKey)
  assert.strictEqual(accept(daniel.publicKey, { ...fake.get(0), head: { ...head, signature: tricked } }), false)
})

test('should return false on garbage instead of throwing', () => {
  for (const reply of [null, undefined, {}, { head: null }, { ...log.get(0), head: { length: 'x' } }]) {
    assert.strictEqual(accept(daniel.publicKey, reply), false)
  }
})
