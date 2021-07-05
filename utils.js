const {
  Hasher,
  Blake2bHasher,
  Reader,
  Script,
  AddressPrefix,
  HashType,
  default: PWCore,
  ChainID,
} = require('@lay2/pw-core')
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
  return `0x${pubKey.toString('hex')}`
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

function pubkeyToUnipassAddress(pubkey, testnet = false) {
  const args = new Blake2bHasher()
    .hash(new Reader(pubkey))
    .serializeJson()
    .slice(0, 42)
  let script
  if (testnet) {
    script = new Script(
      '0x124a60cd799e1fbca664196de46b3f7f0ecb7138133dcaea4893c51df5b02be6',
      args,
      HashType.type,
    )
  } else {
    script = new Script(
      '0x614d40a86e1b29a8f4d8d93b9f3b390bf740803fa19a69f1c95716e029ea09b3',
      args,
      HashType.type,
    )
  }

  PWCore.chainId = testnet ? ChainID.ckb_testnet : ChainID.ckb
  const prefix = testnet ? AddressPrefix.ckt : AddressPrefix.ckb
  return script.toAddress(prefix).toCKBAddress()
}

module.exports = {
  signMessage,
  keyFromPem,

  getMasterAuth,
  getPubkeyHash,
  extractPubkey2,
  pubkeyToNodeRsaKey,
  pubkeyToUnipassAddress,
}
