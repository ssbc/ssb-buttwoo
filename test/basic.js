// SPDX-FileCopyrightText: 2022 Anders Rune Jensen
//
// SPDX-License-Identifier: CC0-1.0

const tape = require('tape')
const ssbKeys = require('ssb-keys')
const bfe = require('ssb-bfe')
const butt2 = require('../format')
const uri2 = require('ssb-uri2')

const keys = ssbKeys.generate(null, 'alice', 'buttwoo-v1')

const authorBFE = Buffer.concat([
  bfe.toTF('feed', 'buttwoo-v1'),
  Buffer.from(keys.public.substring(0, keys.public.indexOf('.')), 'base64'),
])

tape('encode/decode works', function (t) {
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const butt2Msg = butt2.newNativeMsg({
    keys,
    content,
    previous: null,
    timestamp,
    tag: butt2.tags.SSB_FEED,
    hmacKey,
  })

  const jsonMsg = {
    key: butt2.getMsgId(butt2Msg),
    value: butt2.fromNativeMsg(butt2Msg),
    timestamp: Date.now(),
  }
  //console.log(jsonMsg)

  const msgKey =
    'ssb:message/buttwoo-v1/bRjv4LV9CmJp-bXR1nOGJ9Uuo8glEBmnN27ckE2SFJo='

  t.deepEqual(jsonMsg.key, msgKey, 'key is correct')
  t.deepEqual(
    jsonMsg.value.author,
    'ssb:feed/buttwoo-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s=',
    'author is correct'
  )
  t.deepEqual(jsonMsg.value.parent, null, 'correct parent')
  t.deepEqual(jsonMsg.value.sequence, 1, 'correct sequence')
  t.deepEqual(jsonMsg.value.previous, null, 'correct previous')
  t.deepEqual(jsonMsg.value.content, content, 'content is the same')

  const reconstructedButt2msg = butt2.toNativeMsg(jsonMsg.value)
  t.deepEqual(reconstructedButt2msg, butt2Msg, 'can reconstruct')

  const content2 = { type: 'post', text: 'Hello butty world!' }

  const butt2Msg2 = butt2.newNativeMsg({
    keys,
    content: content2,
    previous: { key: msgKey, value: jsonMsg.value },
    timestamp: timestamp + 1,
    tag: butt2.tags.SSB_FEED,
    hmacKey,
  })

  const jsonMsg2 = {
    key: butt2.getMsgId(butt2Msg2),
    value: butt2.fromNativeMsg(butt2Msg2),
    timestamp: Date.now(),
  }
  //console.log(jsonMsg2)

  t.deepEqual(
    jsonMsg2.key,
    'ssb:message/buttwoo-v1/x0HNAvO2ZL6wa7jQr9x_xVlsLQfG2rwwy4YjDRcSPDQ=',
    'key is correct'
  )
  t.deepEqual(
    jsonMsg2.value.author,
    'ssb:feed/buttwoo-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s=',
    'author is correct'
  )
  t.deepEqual(jsonMsg2.value.parent, null, 'correct parent')
  t.deepEqual(jsonMsg2.value.sequence, 2, 'correct sequence')
  t.deepEqual(jsonMsg2.value.previous, msgKey, 'correct previous')
  t.deepEqual(jsonMsg2.value.content, content2, 'content is the same')

  // test slow version as well
  const reconstructedButt2msg2 = butt2.toNativeMsg(jsonMsg2.value)
  t.deepEqual(reconstructedButt2msg2, butt2Msg2, 'can reconstruct')

  t.end()
})

tape('subfeed id', function (t) {
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const butt2Msg = butt2.newNativeMsg({
    keys,
    content,
    parent:
      'ssb:message/buttwoo-v1/bRjv4LV9CmJp-bXR1nOGJ9Uuo8glEBmnN27ckE2SFJo=',
    previous: null,
    timestamp,
    tag: butt2.tags.SUB_FEED,
    hmacKey,
  })

  const feedId = butt2.getFeedId(butt2Msg)
  t.equals(
    feedId,
    'ssb:feed/buttwoo-v1/OAiOTCroL1xFxoCKYaZJDTxhLOHaI1cURm_HSPvEy7s=/bRjv4LV9CmJp-bXR1nOGJ9Uuo8glEBmnN27ckE2SFJo'
  )

  t.end()
})

tape('extract author + sequence', function (t) {
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const butt2Msg = butt2.newNativeMsg({
    keys,
    content,
    previous: null,
    timestamp,
    tag: butt2.tags.SSB_FEED,
    hmacKey,
  })

  const author = butt2.getFeedId(butt2Msg)
  t.deepEqual(bfe.encode(author), authorBFE, 'extracting author works')

  const sequence = butt2.getSequence(butt2Msg)
  t.deepEqual(sequence, 1, 'extracting sequence works')

  t.end()
})

tape('parent', function (t) {
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const butt2Msg = butt2.newNativeMsg({
    keys,
    content,
    previous: null,
    timestamp,
    tag: butt2.tags.SSB_FEED,
    hmacKey,
  })
  const butt2MsgId = butt2.getMsgId(butt2Msg)

  t.ok(butt2.isNativeMsg(butt2Msg), 'isNative works')

  const butt2Msg2 = butt2.newNativeMsg({
    keys,
    parent: butt2MsgId,
    content,
    previous: null,
    timestamp,
    tag: butt2.tags.SSB_FEED,
    hmacKey,
  })

  t.ok(butt2.isNativeMsg(butt2Msg2), 'isNative works with a parent')

  const jsMsgVal = butt2.fromNativeMsg(butt2Msg2)

  t.equal(jsMsgVal.parent, butt2MsgId, 'parent in decoded msg works')

  t.end()
})

tape('validate', (t) => {
  const hmacKey = null
  const timestamp = 1652037377204

  const butt2Msg1 = butt2.newNativeMsg({
    keys,
    content: { type: 'post', text: 'Hello world!' },
    previous: null,
    timestamp,
    tag: butt2.tags.SSB_FEED,
    hmacKey,
  })

  butt2.validate(butt2Msg1, null, hmacKey, (err1) => {
    t.error(err1, 'no error')

    const butt2Msg2 = butt2.newNativeMsg({
      keys,
      content: { type: 'post', text: 'Hello butty world!' },
      previous: {
        key: butt2.getMsgId(butt2Msg1),
        value: butt2.fromNativeMsg(butt2Msg1),
      },
      timestamp: timestamp + 1,
      tag: butt2.tags.END_OF_FEED,
      hmacKey,
    })

    butt2.validate(butt2Msg2, butt2Msg1, hmacKey, (err2) => {
      t.error(err2, 'no error')

      const butt2Msg3 = butt2.newNativeMsg({
        keys,
        content: { type: 'post', text: 'Sneaky world!' },
        previous: {
          key: butt2.getMsgId(butt2Msg2),
          value: butt2.fromNativeMsg(butt2Msg2),
        },
        timestamp: timestamp + 2,
        tag: butt2.tags.SSB_FEED,
        hmacKey,
      })
      butt2.validate(butt2Msg3, butt2Msg2, hmacKey, (err3) => {
        t.equal(
          err3.message,
          'invalid message: previous message is a tombstone',
          'cant extend ended feed'
        )
        t.end()
      })
    })
  })
})

tape('validate many', function (t) {
  const N = 4000
  const M = 100
  const hmacKey = null
  const content = { type: 'post', text: 'Hello world!' }
  const timestamp = 1652037377204

  const nativeMsgs = []
  let previous = null
  for (let i = 0; i < N; ++i) {
    const butt2Msg = butt2.newNativeMsg({
      keys,
      content,
      previous,
      timestamp: timestamp + i,
      tag: butt2.tags.SSB_FEED,
      hmacKey,
    })
    previous = {
      key: butt2.getMsgId(butt2Msg),
      value: butt2.fromNativeMsg(butt2Msg),
    }
    nativeMsgs.push(butt2Msg)
  }

  let isOk = true
  let err = null

  // validate single all, take time
  const startSingle = new Date()
  for (let i = 0; i < N; ++i) {
    const prevNativeMsg = i === 0 ? null : nativeMsgs[i - 1]
    if ((err = butt2.validateSync(nativeMsgs[i], prevNativeMsg, hmacKey))) {
      console.log(err)
      isOk = false
      break
    }
  }
  const singleTime = new Date() - startSingle

  t.equal(isOk, true, 'validateSingle completes in ' + singleTime + ' ms')

  isOk = true
  const startBatch = new Date()
  for (let i = 0; i < N; i += M) {
    const prevNativeMsg = i === 0 ? null : nativeMsgs[i - 1]
    if (
      (err = butt2.validateBatchSync(
        nativeMsgs.slice(i, i + M),
        prevNativeMsg,
        hmacKey
      ))
    ) {
      console.log(err)
      isOk = false
      break
    }
  }
  const batchTime = new Date() - startBatch

  t.equal(isOk, true, 'validateBatch completes in ' + batchTime + ' ms')
  t.ok(
    batchTime < singleTime,
    'batch validation is faster than single validation'
  )

  t.end()
})
