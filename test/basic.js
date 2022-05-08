const tape = require('tape')
const ssbKeys = require('ssb-keys')
const bipf = require('bipf')
const butt2 = require('../')

tape('encode/decode works', function (t) {
  const keys = {
    curve: 'ed25519',
    public: 'TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=.ed25519',
    private: 'waCfThHBkSmFfzZANABv/O9DYtcxUuHc/zoWoseXcidMF4uwubeLO3JirtWCNVmfxGbB7jeYRc92iXAqNvZ4Uw==.ed25519',
    id: '@TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=.ed25519'
  }
  const content = { type: 'post', text: 'Hello world!' }
  const backlinksBFE = Buffer.from([6,2]) //  null
  const timestamp = 1652037377204

  const [msgKeyBFE, butt2Msg] = butt2.encodeNew(content, keys, 1, backlinksBFE, timestamp, null)

  const data = butt2.extractData(butt2Msg)
  const msg = butt2.butt2ToBipf(data, msgKeyBFE)

  const jsonMsg = bipf.decode(msg, 0)
  
  //console.log(jsonMsg)

  t.deepEqual(jsonMsg.key, 'ssb:message/butt2-v1/kB_IWWTikAbTVBcL6EMWcvdvdqtNWjdPBbXC7_xHW50=', 'key is correct')
  t.deepEqual(jsonMsg.value.author, 'ssb:feed/butt2-v1/TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=', 'author is correct')
  t.deepEqual(jsonMsg.value.content, content, 'content is the same')

  t.end()
})

tape('validate', function (t) {
  const keys = {
    curve: 'ed25519',
    public: 'TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=.ed25519',
    private: 'waCfThHBkSmFfzZANABv/O9DYtcxUuHc/zoWoseXcidMF4uwubeLO3JirtWCNVmfxGbB7jeYRc92iXAqNvZ4Uw==.ed25519',
    id: '@TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=.ed25519'
  }
  const content = { type: 'post', text: 'Hello world!' }
  const backlinksBFE = Buffer.from([6,2]) //  null
  const timestamp = 1652037377204

  const [msgKeyBFE1, butt2Msg1] = butt2.encodeNew(content, keys, 1, backlinksBFE, timestamp, null)

  const data = butt2.extractData(butt2Msg1)
  const msgKeyBFEValidate1 = butt2.validateSingle(data, null, null, null)

  t.deepEqual(msgKeyBFE1, msgKeyBFEValidate1, 'validate no err, generates correct key')

  const content2 = { type: 'post', text: 'Hello butty world!' }
  const timestamp2 = 1652037377205

  const [msgKeyBFE2, butt2Msg2] = butt2.encodeNew(content2, keys, 2, msgKeyBFE1, timestamp2, null)

  const data2 = butt2.extractData(butt2Msg2)
  const msgKeyBFEValidate2 = butt2.validateSingle(data2, data, msgKeyBFEValidate1, null)

  t.deepEqual(msgKeyBFE2, msgKeyBFEValidate2, 'validate no err, generates correct key')

  t.end()
})
