// Who can I trust in a network with no server? The whole story, step by step.
//
//   node example/demo.js
//
// Daniel writes a log. Mallory is a stranger who has a copy and serves it. Nobody trusts
// Mallory, and nobody needs to: every answer is checked against Daniel's public key.

const crypto = require('node:crypto')
const { keyPair, challenge, respond, check } = require('../lib/handshake')
const { proof } = require('../lib/merkle')
const { Writer, accept, message } = require('../lib/log')
const { fork, rewrote } = require('../lib/fork')
const { nodeId, distance, leadingZeros, Tokens } = require('../lib/node')

const color = process.stdout.isTTY
const paint = (code, text) => (color ? `\x1b[${code}m${text}\x1b[0m` : text)
const title = text => console.log(paint(1, `\n${text}`))
const ok = (text, yes) => console.log(`  ${yes ? paint(32, 'accepted') : paint(31, 'rejected')}  ${text}`)
const note = text => console.log(paint(2, `            ${text}`))
const short = buf => buf.toString('hex').slice(0, 12)

function writer(keys, blocks) {
  const w = new Writer(keys)
  for (const b of blocks) w.append(b)
  return w
}

const daniel = keyPair()
const impostor = keyPair()
console.log(`daniel's public key ${daniel.publicKey}`)

// 1. Is this peer really Daniel?
title('1. handshake: prove you own the key')
let nonce = challenge()
ok('daniel signs our fresh nonce', check(nonce, respond(nonce, daniel.secretKey), daniel.publicKey))
ok(
  'an impostor claims to be daniel, signs with its own key',
  check(nonce, respond(nonce, impostor.secretKey), daniel.publicKey),
)
const recorded = respond(nonce, daniel.secretKey)
nonce = challenge()
ok('someone replays an answer daniel gave earlier', check(nonce, recorded, daniel.publicKey))
note('a new nonce every time makes old answers useless')

// 2. Can I take a block from a stranger?
title('2. signed log: take a block from anyone')
const log = writer(daniel, ['hello', 'how are you?', 'meet at 8', 'bring the keys', 'see you'])
const head = log.head()
console.log(`  daniel signs the head: length ${head.length}, root ${short(head.root)}...`)
const reply = log.get(2) // mallory has a copy and serves block 2
console.log(`  mallory serves block 2 "${reply.block}" with ${reply.proof.length} hashes of proof`)
ok("block 2, checked against daniel's key, not mallory's word", accept(daniel.publicKey, reply))
ok('mallory changes it to "meet at 9"', accept(daniel.publicKey, { ...reply, block: 'meet at 9' }))
const fake = writer(impostor, ['hello', 'how are you?', 'meet at 9', 'bring the keys', 'see you'])
ok('mallory signs her own version of the log', accept(daniel.publicKey, fake.get(2)))
const big = Array.from({ length: 100_000 }, (_, i) => `block ${i}`)
note(`a log of ${big.length.toLocaleString('en')} blocks needs only ${proof(big, 54_321).length} hashes to prove one`)

// 3. The signature that was asked for something else
title('3. namespaces: a signature only counts for its purpose')
const evil = writer(impostor, ['evil']).head()
const tricked = respond(message(evil.length, evil.root), daniel.secretKey) // a fake root sent as a "nonce"
ok(
  "daniel's handshake answer passed off as a signed head",
  accept(daniel.publicKey, { block: 'evil', index: 0, proof: [], head: { ...evil, signature: tricked } }),
)
note('handshake signs under trust/handshake, the log under trust/log')

// 4. What if Daniel himself lies?
title('4. forks: catch the author lying')
const version1 = writer(daniel, ['a', 'b', 'c', 'd', 'e'])
const version2 = writer(daniel, ['a', 'b', 'c', 'd', 'X'])
const toPeer1 = version1.head()
const toPeer2 = version2.head()
console.log(`  peer 1 got length 5, root ${short(toPeer1.root)}...`)
console.log(`  peer 2 got length 5, root ${short(toPeer2.root)}...`)
ok('peer 1 alone: block 4 "e" checks out', accept(daniel.publicKey, version1.get(4)))
ok('peer 2 alone: block 4 "X" checks out', accept(daniel.publicKey, version2.get(4)))
note('each peer alone sees nothing wrong')
console.log(`  ${paint(31, 'fork     ')}  the peers compare heads: ${fork(daniel.publicKey, toPeer1, toPeer2)}`)
note('same length, two roots, two signatures: a proof anyone can check, no vote needed')
const before = writer(daniel, ['a', 'b', 'c']).head()
const rewritten = ['a', 'X', 'c', 'd', 'e']
console.log(
  `  ${paint(31, 'rewrite  ')}  3 blocks became 5, but block 1 changed: ${rewrote(daniel.publicKey, before, writer(daniel, rewritten).head(), rewritten)}`,
)

// 5. Can a node pick its place in the DHT?
title('5. dht: the id comes from the address')
const target = crypto.randomBytes(32)
console.log(`  node at 1.2.3.4:49737 has id ${short(nodeId('1.2.3.4', 49737))}...  nobody chooses it`)
let bestBits = 0
for (let port = 1; port <= 65535; port++) {
  bestBits = Math.max(bestBits, leadingZeros(distance(nodeId('1.2.3.4', port), target)))
}
note(`trying all 65535 ports of one ip, the best id shares ${bestBits} bits with a random key`)
const tokens = new Tokens()
const token = tokens.create('1.2.3.4') // sent in our reply to 1.2.3.4
ok('a write from 1.2.3.4 echoing the token it got', tokens.check('1.2.3.4', token))
ok('a write with a forged source 5.6.7.8 and no reply ever received', tokens.check('5.6.7.8', crypto.randomBytes(32)))
note('the token went to the real ip, a spoofer never sees it')

title('nothing above trusted the sender. only keys, hashes and signatures.')
