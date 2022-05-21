const tape = require('tape')
const ssbKeys = require('ssb-keys')
const bipf = require('bipf')
const bfe = require('ssb-bfe')
const butt2 = require('../')

const BFE_NIL = Buffer.from([6,2])

const keys = {
  curve: 'ed25519',
  public: 'TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=.ed25519',
  private: 'waCfThHBkSmFfzZANABv/O9DYtcxUuHc/zoWoseXcidMF4uwubeLO3JirtWCNVmfxGbB7jeYRc92iXAqNvZ4Uw==.ed25519',
  id: '@TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=.ed25519'
}

const authorBFE = Buffer.concat([
  bfe.toTF('feed', 'buttwoo-v1'),
  Buffer.from(keys.public.substring(0, keys.public.indexOf('.')), "base64")
])

tape('encode/decode works', function (t) {
  const hmacKey = null
  const tag = butt2.tags.SSB_FEED

  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const [msgKeyBFE, butt2Msg] = butt2.encodeNew(content, keys, null, 1, null, timestamp, tag, hmacKey)

  const data = butt2.extractData(butt2Msg)
  const msg = butt2.butt2ToBipf(data, msgKeyBFE)

  const jsonMsg = bipf.decode(msg, 0)
  
  //console.log(jsonMsg)

  const msgKey = 'ssb:message/buttwoo-v1/dN-xH6liM_cGDA-43YSY6LUCb7CCl_G6a83F7UbsN-E='

  t.deepEqual(jsonMsg.key, msgKey, 'key is correct')
  t.deepEqual(jsonMsg.value.author, 'ssb:feed/buttwoo-v1/TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=', 'author is correct')
  t.deepEqual(jsonMsg.value.parent, null, 'correct parent')
  t.deepEqual(jsonMsg.value.sequence, 1, 'correct sequence')
  t.deepEqual(jsonMsg.value.previous, null, 'correct previous')
  t.deepEqual(jsonMsg.value.content, content, 'content is the same')

  const reconstructedButt2msg = butt2.bipfToButt2(msg)
  t.deepEqual(reconstructedButt2msg, butt2Msg, 'can reconstruct')

  const content2 = { type: 'post', text: 'Hello butty world!' }

  const [msgKeyBFE2, butt2Msg2] = butt2.encodeNew(content2, keys, null, 2, msgKeyBFE, timestamp+1, tag, hmacKey)

  const data2 = butt2.extractData(butt2Msg2)
  const msg2 = butt2.butt2ToBipf(data2, msgKeyBFE2)

  const jsonMsg2 = bipf.decode(msg2, 0)

  //console.log(jsonMsg2)

  t.deepEqual(jsonMsg2.key, 'ssb:message/buttwoo-v1/dQ8CN5zDyR0ubZ94kt_sQIHA3_rc9-xfu1HWmQTb46Q=', 'key is correct')
  t.deepEqual(jsonMsg2.value.author, 'ssb:feed/buttwoo-v1/TBeLsLm3iztyYq7VgjVZn8Rmwe43mEXPdolwKjb2eFM=', 'author is correct')
  t.deepEqual(jsonMsg2.value.parent, null, 'correct parent')
  t.deepEqual(jsonMsg2.value.sequence, 2, 'correct sequence')
  t.deepEqual(jsonMsg2.value.previous, msgKey, 'correct previous')
  t.deepEqual(jsonMsg2.value.content, content2, 'content is the same')

  // test slow version as well
  const reconstructedButt2msg2 = butt2.msgValToButt2(jsonMsg2.value)
  t.deepEqual(reconstructedButt2msg2, butt2Msg2, 'can reconstruct')

  t.end()
})

tape('extract author + sequence', function (t) {
  const hmacKey = null

  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const [msgKeyBFE, butt2Msg] = butt2.encodeNew(content, keys, null, 1, null, timestamp,
                                                butt2.tags.SSB_FEED, hmacKey)

  const author = butt2.extractAuthor(butt2Msg)
  t.deepEqual(author, authorBFE, 'extracting author works')

  const parent = butt2.extractParent(butt2Msg)
  t.deepEqual(parent, BFE_NIL, 'extracting parent works')

  const sequence = butt2.extractSequence(butt2Msg)
  t.deepEqual(sequence, 1, 'extracting sequence works')

  t.end()
})

tape('validate', function (t) {
  const hmacKey = null

  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const [msgKeyBFE1, butt2Msg1] = butt2.encodeNew(content, keys, null, 1, null, timestamp,
                                                  butt2.tags.SSB_FEED, hmacKey)

  const data = butt2.extractData(butt2Msg1)
  const err1 = butt2.validateSingle(data, null, null, null)
  const msgKeyBFEValidate1 = butt2.hash(data)

  t.notOk(err1)
  t.deepEqual(msgKeyBFE1, msgKeyBFEValidate1, 'validate no err, generates correct key')

  const content2 = { type: 'post', text: 'Hello butty world!' }

  const [msgKeyBFE2, butt2Msg2] = butt2.encodeNew(content2, keys, null, 2, msgKeyBFE1, timestamp+1,
                                                  butt2.tags.END_OF_FEED, hmacKey)

  const data2 = butt2.extractData(butt2Msg2)
  const err2 = butt2.validateSingle(data2, data, msgKeyBFEValidate1, null)
  const msgKeyBFEValidate2 = butt2.hash(data2)

  t.notOk(err2)
  t.deepEqual(msgKeyBFE2, msgKeyBFEValidate2, 'validate no err, generates correct key')

  const content3 = { type: 'post', text: 'Sneaky world!' }

  const [msgKeyBFE3, butt2Msg3] = butt2.encodeNew(content3, keys, null, 3, msgKeyBFE2, timestamp+2,
                                                  butt2.tags.SSB_FEED, hmacKey)
  const data3 = butt2.extractData(butt2Msg3)
  const err = butt2.validateSingle(data3, data2, msgKeyBFEValidate2, null)

  t.deepEqual('Feed already terminated', err.message, 'Unable to extend terminated feed')
  t.end()
})

tape('validate many', function (t) {
  const hmacKey = null

  const N = 1000

  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const msgKeys = []
  const messages = []
  const datas = []

  for (let i = 0; i < N; ++i) {
    const previousBFE = i === 0 ? null : msgKeys[i-1]

    const [msgKeyBFE, butt2Msg] = butt2.encodeNew(content, keys, null, i+1, previousBFE, timestamp+i,
                                                  butt2.tags.SSB_FEED, hmacKey)

    const data = butt2.extractData(butt2Msg)
    datas.push(data)

    msgKeys.push(msgKeyBFE)
    messages.push(butt2Msg)
  }

  var isOk = true

  // validate single all, take time
  const startSingle = new Date()
  for (let i = 0; i < N; ++i) {
    const prevData = i === 0 ? null : datas[i-1]
    const prevMsgKey = i === 0 ? null : msgKeys[i-1]

    const validate = butt2.validateSingle(datas[i], prevData, prevMsgKey, hmacKey)
    if (typeof validate === 'string') {
      isOk = false
      break
    }
  }
  const singleTime = (new Date()) - startSingle

  t.equal(isOk, true, 'validateSingle completes in ' + singleTime + ' ms')

  const result = []
  const startBatch = new Date()
  for (let i = 0; i < N; i += 25) {
    const prevData = i === 0 ? null : datas[i-1]
    const prevMsgKey = i === 0 ? null : msgKeys[i-1]
    const keys = butt2.validateBatch(datas.slice(i, i+25), prevData, prevMsgKey, hmacKey)
    for (var j = 0; j < keys.length; ++j)
      result.push(keys[j])
  }
  const batchTime = (new Date()) - startBatch

  t.ok(Array.isArray(result), 'validateBatch completes in ' + batchTime + ' ms')
  t.ok(batchTime < singleTime, 'batch validation is faster than single validation')

  t.end()
})
