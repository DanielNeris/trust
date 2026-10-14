// Can I trust a block that came from a stranger?
//
// In a P2P network you rarely get data from its author. You download block 5 of Daniel's
// log from whoever has a copy. Signing every block would work, but a million blocks would
// mean a million signatures. So the blocks go into a Merkle tree and the author signs only
// the root:
//
//               root            <- the author signs only this
//             /      \
//          h01        h2         an odd node goes up alone
//         /   \        |
//       h0    h1      h2        <- leaf(block)
//
// Change one byte of any block and its leaf changes, then its parent, all the way up:
// the root no longer matches the signature.
//
// Leaves and parents hash with different prefixes (0x00 and 0x01). Without them, a parent
// (64 bytes: two hashes) could be passed off as a block whose leaf hash is the same value.
//
// An odd node goes up alone, it's never paired with itself. Bitcoin duplicated it, and two
// different lists ended up with the same root (CVE-2012-2459).
//
// To prove one block, you don't send the whole log, only the siblings on the way up. For
// block 2 of 5: h3, then h01, then h4. The reader hashes its way up and must land on the
// signed root. With a million blocks that's about 20 hashes.

const crypto = require('node:crypto')

const LEAF = Buffer.from([0x00])
const PARENT = Buffer.from([0x01])

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest()
}

// The hash of one block. Strings are taken as utf-8.
function leaf(data) {
  return sha256(Buffer.concat([LEAF, Buffer.from(data)]))
}

// The hash of two child hashes.
function parent(left, right) {
  return sha256(Buffer.concat([PARENT, left, right]))
}

// The root of a list of blocks, level by level until one is left. An empty log has no root.
function root(blocks) {
  if (blocks.length === 0) return null

  let level = blocks.map(leaf)
  while (level.length > 1) level = up(level)
  return level[0]
}

// One level up: pair the nodes, the odd one goes up alone.
function up(level) {
  const next = []
  for (let i = 0; i < level.length; i += 2) {
    if (i + 1 < level.length) next.push(parent(level[i], level[i + 1]))
    else next.push(level[i]) // odd one out: goes up alone
  }
  return next
}

// The siblings on the way up from block index: all a stranger needs to send with the block.
// left tells on which side the sibling goes, because parent(a, b) is not parent(b, a).
function proof(blocks, index) {
  if (index < 0 || index >= blocks.length) return null
  const path = []
  let level = blocks.map(leaf)

  let i = index

  while (level.length > 1) {
    const sibling = i ^ 1 // XOR 1 flips the last bit: 2 <-> 3, 4 <-> 5
    if (sibling < level.length) path.push({ hash: level[sibling], left: sibling < i })
    level = up(level)
    i = Math.floor(i / 2) // our position one level up
  }
  return path
}

// Hash the block up the path and compare with the signed root.
// Never throws: a proof from a stranger can be garbage.
function verify(block, path, expected) {
  try {
    let cur = leaf(block)
    for (const step of path) {
      cur = step.left ? parent(step.hash, cur) : parent(cur, step.hash)
    }
    return cur.equals(expected)
  } catch {
    return false
  }
}

module.exports = { leaf, parent, root, proof, verify }
