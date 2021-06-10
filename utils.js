const { Hasher, Blake2bHasher } = require('@lay2/pw-core')
const NodeRSA = require('node-rsa')

async function extractPubkey2(privaKey) {
  const data = await privaKey.exportKey('components-private')
  // console.log('data', data);

  const e = data.e.toString(16).padStart(8, '0')
  const n = data.n.slice(1)
  const size = n.length * 8

  // console.log('size', size);
  // console.log('e', e);

  const sizeVec = Buffer.alloc(4)
  sizeVec.writeUInt32LE(size, 0)
  const eVec = Buffer.from(e, 'hex').reverse()
  const nVec = n.reverse()

  const pubKey = Buffer.concat([sizeVec, eVec, nVec])
  // console.log('pubKey', pubKey.toString('hex'));
  return pubKey.toString('hex')
}

function signMessage(masterKey, messageHex) {
  const sig =
    '0x' +
    masterKey.sign(Buffer.from(messageHex.replace('0x', ''), 'hex'), 'hex')

  console.log('authorization sig', sig)

  return sig
}

function keyFromPem(pem) {
  const key = new NodeRSA(pem)
  key.setOptions({ signingScheme: 'pkcs1-sha256' })
  return key
}

async function getMasterAuth(masterKey, masterPubkey, localPubkey) {
  const sig = signMessage(masterKey, localPubkey)

  console.log('masterPubkey2', masterPubkey)
  const auth = Buffer.concat([
    Buffer.from(masterPubkey.replace('0x', ''), 'hex'),
    Buffer.from(sig.replace('0x', ''), 'hex'),
  ])

  return `0x${auth.toString('hex')}`
}

function getPubkeyHash(pubkey) {
  const blake2b = new Blake2bHasher()
  blake2b.update(new Reader(`0x${pubkey.replace('0x', '')}`))
  return blake2b.digest().serializeJson()
}

function pubkeyToNodeRsaKey(pubkey) {
  const NodeRSA = require('node-rsa')
  const key = new NodeRSA()

  const pubkeyBuffer = Buffer.from(pubkey.replace('0x', ''), 'hex')

  const e = pubkeyBuffer.slice(4, 8).readUInt32LE()
  const n = pubkeyBuffer.slice(8).reverse()

  key.importKey(
    {
      e,
      n,
    },
    'components-public',
  )

  key.setOptions({ signingScheme: 'pkcs1-sha256' })

  return key
}

module.exports = {
  signMessage,
  keyFromPem,
  getMasterAuth,
  getPubkeyHash,
  extractPubkey2,
  pubkeyToNodeRsaKey,
}
