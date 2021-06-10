const { pubkeyToNodeRsaKey } = require('./utils')
class Verifier {
  verify(messageHex, unipassSig) {
    // TODO: messageHex check
    // TODO: unipassSig length check

    let buffer = Buffer.from(unipassSig.replace('0x', ''), 'hex')

    const flag = buffer.slice(0, 1)
    buffer = buffer.slice(1)

    const masterPubkey = buffer.slice(0, 256 + 4 + 4)
    buffer = buffer.slice(256 + 4 + 4)

    const auth = buffer.slice(0, 256)
    buffer = buffer.slice(256)

    const localPubkey = buffer.slice(0, 256 + 4 + 4)
    buffer = buffer.slice(256 + 4 + 4)

    const sig = buffer.slice(0, 256)

    console.log('masterPubkey', masterPubkey.toString('hex'))
    console.log('localPubkey', localPubkey.toString('hex'))

    const ret1 = this.verifyRsaSig(
      masterPubkey,
      localPubkey.toString('hex'),
      auth,
    )
    console.log('ret1', ret1)
    const ret2 = this.verifyRsaSig(localPubkey, messageHex, sig)
    console.log('ret2', ret2)

    return ret1 && ret2
  }

  verifyRsaSig(pubKey, messageHex, sig) {
    const key = pubkeyToNodeRsaKey(pubKey.toString('hex'))

    return key.verify(Buffer.from(messageHex.replace('0x', ''), 'hex'), sig)
  }
}

module.exports = { Verifier }
