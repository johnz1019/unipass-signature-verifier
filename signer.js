const { signMessage } = require('./utils')

// this signer will generate a signature this same as signer of unipass.com
class Signer {
  /* ---------------------------mock unipass sign start-------------------------------- */
  localKey
  masterKey
  masterPubkey
  localPubkey

  setKeys(masterKey, masterPubkey, localKey, localPubkey) {
    this.localKey = localKey
    this.masterKey = masterKey
    this.masterPubkey = masterPubkey
    this.localPubkey = localPubkey
  }

  rsaSign(message) {
    console.log('tx digest message', message)

    const sig = this.localKey.sign(
      Buffer.from(message.replace('0x', ''), 'hex'),
      'hex',
    )
    // const masterPubkey;
    const authorization = signMessage(this.masterKey, this.localPubkey)

    console.log('masterPubkey: ', this.masterPubkey)
    console.log('authorization: ', authorization)
    console.log('localPubkey: ', this.localPubkey)
    console.log('localsig: ', sig)
    // const localPubkey;
    // const sig;

    const lock = Buffer.concat([
      Buffer.from(this.masterPubkey.replace('0x', ''), 'hex'),
      Buffer.from(authorization.replace('0x', ''), 'hex'),
      Buffer.from(this.localPubkey.replace('0x', ''), 'hex'),
      Buffer.from(sig.replace('0x', ''), 'hex'),
    ])
    const ret = '0x01' + lock.toString('hex')
    console.log('ret', ret)
    return ret
  }
  /* ---------------------------mock unipass sign end-------------------------------- */
}

module.exports = { Signer }
