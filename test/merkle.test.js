const test = require('node:test')
const assert = require('node:assert')
const { leaf, parent, root, proof, verify } = require('../lib/merkle')

test('should hash a leaf as a 32-byte buffer', () => {
  assert.ok(Buffer.isBuffer(leaf('a')))
  assert.strictEqual(leaf('a').length, 32)
  assert.deepStrictEqual(leaf('a'), leaf(Buffer.from('a'))) // a string is its utf-8 bytes
})

test('should not give a leaf and a parent the same hash for the same bytes', () => {
  const a = leaf('a')
  const b = leaf('b')
  // a block made of exactly the bytes of two hashes: without the prefixes it would look like a parent
  assert.notDeepStrictEqual(leaf(Buffer.concat([a, b])), parent(a, b))
})

test('should have no root for an empty log', () => {
  assert.strictEqual(root([]), null)
})

test('should use the leaf itself as the root of a single block', () => {
  assert.deepStrictEqual(root(['a']), leaf('a'))
})

test('should build the tree level by level, the odd one going up alone', () => {
  const [h0, h1, h2, h3, h4] = ['a', 'b', 'c', 'd', 'e'].map(leaf)
  assert.deepStrictEqual(root(['a', 'b']), parent(h0, h1))
  assert.deepStrictEqual(root(['a', 'b', 'c']), parent(parent(h0, h1), h2))
  assert.deepStrictEqual(root(['a', 'b', 'c', 'd']), parent(parent(h0, h1), parent(h2, h3)))
  assert.deepStrictEqual(root(['a', 'b', 'c', 'd', 'e']), parent(parent(parent(h0, h1), parent(h2, h3)), h4))
})

test('should change the root when any block changes', () => {
  const blocks = ['a', 'b', 'c', 'd', 'e']
  const original = root(blocks)
  for (let i = 0; i < blocks.length; i++) {
    const changed = [...blocks]
    changed[i] = 'x'
    assert.notDeepStrictEqual(root(changed), original, `block ${i}`)
  }
})

test('should change the root when the order changes', () => {
  assert.notDeepStrictEqual(root(['a', 'b', 'c']), root(['b', 'a', 'c']))
})

test('should not give the same root to a list and that list with its last block repeated', () => {
  // the Bitcoin bug: duplicating the odd node made [a, b, c] and [a, b, c, c] share a root
  assert.notDeepStrictEqual(root(['a', 'b', 'c']), root(['a', 'b', 'c', 'c']))
})

const blocks = ['a', 'b', 'c', 'd', 'e']

test('should prove every block of the log against the root', () => {
  const r = root(blocks)
  for (let i = 0; i < blocks.length; i++) assert.strictEqual(verify(blocks[i], proof(blocks, i), r), true, `block ${i}`)
})

test('should give only the siblings on the way up, with their side', () => {
  const [h0, h1, h2, h3, h4] = blocks.map(leaf)
  assert.deepStrictEqual(proof(blocks, 2), [
    { hash: h3, left: false },
    { hash: parent(h0, h1), left: true },
    { hash: h4, left: false },
  ])
  assert.deepStrictEqual(proof(blocks, 4), [{ hash: parent(parent(h0, h1), parent(h2, h3)), left: true }]) // the odd one skips two levels
})

test('should not accept a changed block, a wrong position or a wrong root', () => {
  const r = root(blocks)
  const p = proof(blocks, 2)
  assert.strictEqual(verify('x', p, r), false)
  assert.strictEqual(verify('c', proof(blocks, 3), r), false)
  assert.strictEqual(verify('c', p, root(['a', 'b', 'c'])), false)
  const flipped = p.map(step => ({ ...step, left: !step.left })) // right hashes, wrong sides
  assert.strictEqual(verify('c', flipped, r), false)
})

test('should have no proof for a position outside the log', () => {
  assert.strictEqual(proof(blocks, -1), null)
  assert.strictEqual(proof(blocks, 5), null)
  assert.strictEqual(proof([], 0), null)
})

test('should return false on garbage instead of throwing', () => {
  const r = root(blocks)
  assert.strictEqual(verify('c', null, r), false)
  assert.strictEqual(verify('c', [{ hash: 'not a buffer', left: true }], r), false)
  assert.strictEqual(verify('c', proof(blocks, 2), null), false)
})
