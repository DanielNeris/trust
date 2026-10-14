const test = require('node:test')
const assert = require('node:assert')
const { nodeId, distance, Tokens } = require('../lib/node')

test('should derive the same 32-byte id from the same address, every time', () => {
  const id = nodeId('1.2.3.4', 49737)
  assert.strictEqual(id.length, 32)
  assert.deepStrictEqual(nodeId('1.2.3.4', 49737), id) // any node computes the same id for this address
})

test('should give another id to another port or another ip', () => {
  const id = nodeId('1.2.3.4', 49737)
  assert.notDeepStrictEqual(nodeId('1.2.3.4', 49738), id)
  assert.notDeepStrictEqual(nodeId('1.2.3.5', 49737), id)
})

test('should measure zero distance to itself, and the same both ways', () => {
  const a = nodeId('1.2.3.4', 1)
  const b = nodeId('5.6.7.8', 2)
  assert.deepStrictEqual(distance(a, a), Buffer.alloc(32))
  assert.deepStrictEqual(distance(a, b), distance(b, a))
})

test('should put an id that shares more leading bits closer', () => {
  const target = Buffer.alloc(32) // 0000...
  const near = Buffer.alloc(32)
  near[1] = 0xff // differs from the second byte on
  const far = Buffer.alloc(32)
  far[0] = 0x01 // differs already in the first byte
  assert.ok(Buffer.compare(distance(target, near), distance(target, far)) < 0)
})

test('should accept the token it gave to that host', () => {
  const tokens = new Tokens()
  assert.strictEqual(tokens.check('1.2.3.4', tokens.create('1.2.3.4')), true)
})

test('should not accept a token given to another host', () => {
  // the spoofer: it got a token at its own ip, then claims to be 1.2.3.4
  const tokens = new Tokens()
  assert.strictEqual(tokens.check('1.2.3.4', tokens.create('6.6.6.6')), false)
})

test('should not accept a token made by another node', () => {
  // without the secret nobody can compute it, not even another honest node
  const mine = new Tokens()
  const theirs = new Tokens()
  assert.strictEqual(mine.check('1.2.3.4', theirs.create('1.2.3.4')), false)
})

test('should return false on garbage instead of throwing', () => {
  const tokens = new Tokens()
  const good = tokens.create('1.2.3.4')
  for (const token of [good.subarray(0, 16), Buffer.alloc(32), 'not a buffer', null, undefined]) {
    assert.strictEqual(tokens.check('1.2.3.4', token), false)
  }
})
