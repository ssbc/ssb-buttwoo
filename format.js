// SPDX-FileCopyrightText: 2022 Anders Rune Jensen
//
// SPDX-License-Identifier: LGPL-3.0-only

const bipf = require('bipf')
const bfe = require('ssb-bfe')
const SSBURI = require('ssb-uri2')
const varint = require('fast-varint')
const ssbKeys = require('ssb-keys')
const makeContentHash = require('./content-hash')
const {
  validate,
  validateBatch,
  validateSync,
  validateBatchSync,
} = require('./validation')
const { getMsgId } = require('./get-msg-id')
const { extract } = require('./extract')

function _base64ToBuffer(str) {
  var i = str.indexOf('.')
  return Buffer.from(str.substring(0, i), 'base64')
}

const BUTTWOO_FEED_TF = bfe.toTF('feed', 'buttwoo-v1')
const BIPF_TAG_SIZE = 3
const BIPF_TAG_MASK = 7
const BIPF_STRING_TYPE = 0b000

const name = 'buttwoo-v1'
const encodings = ['js', 'bipf']

const _feedIdCache = new WeakMap()
const _jsMsgValCache = new WeakMap()
const _bipfMsgValCache = new WeakMap()

function getFeedId(nativeMsg) {
  if (_feedIdCache.has(nativeMsg)) {
    return _feedIdCache.get(nativeMsg)
  }
  const [encodedValue] = extract(nativeMsg)
  let authorBFE
  let parentBFE
  bipf.iterate(encodedValue, 0, (b, pointer) => {
    if (!authorBFE) {
      authorBFE = bipf.decode(b, pointer)
    } else if (!parentBFE) {
      parentBFE = bipf.decode(b, pointer)
      return true // abort the bipf.iterate
    }
  })
  const author = bfe.decode(authorBFE)
  const parent = bfe.decode(parentBFE)
  if (parent) {
    const { data } = SSBURI.decompose(parent)
    const feedId = author + '/' + data
    _feedIdCache.set(nativeMsg, feedId)
    return author + '/' + data
  } else {
    _feedIdCache.set(nativeMsg, author)
    return author
  }
}

function getSequence(nativeMsg) {
  const [encodedVal] = extract(nativeMsg)
  let sequence
  let i = 0
  bipf.iterate(encodedVal, 0, (b, pointer) => {
    if (i++ === 2) {
      sequence = bipf.decode(b, pointer)
      return true // abort the bipf.iterate
    }
  })
  return sequence
}

function isNativeMsg(x) {
  if (!Buffer.isBuffer(x)) return false
  if (x.length === 0) return false
  const type = bipf.getEncodedType(x)
  if (type !== bipf.types.array) return false
  // Peek into the BFE header of the author field
  const bfeHeader = x.subarray(8, 10)
  return bfeHeader.compare(BUTTWOO_FEED_TF) === 0
}

function isAuthor(author) {
  // FIXME: ssb-uri2 needs to be updated so that it supports both
  // ssb:feed/buttwoo-v1/$AUTHOR and ssb:feed/buttwoo-v1/$AUTHOR/$PARENT
  // Then we can delete the right-hand side of the OR.
  if (typeof author !== 'string') return false
  return (
    author.startsWith('ssb:feed/buttwoo-v1/') ||
    SSBURI.isButtwooV1FeedSSBURI(author)
  )
}

function toPlaintextBuffer(opts) {
  return bipf.allocAndEncode(opts.content)
}

const tags = {
  SSB_FEED: 0,
  SUB_FEED: 1,
  END_OF_FEED: 2,
}

function newNativeMsg(opts) {
  // FIXME: validate opts.tag
  const authorBFE = bfe.encode(opts.keys.id)
  const previous = opts.previous || { key: null, value: { sequence: 0 } }
  const previousBFE = bfe.encode(previous.key)
  const contentBuffer = bipf.allocAndEncode(opts.content)
  const contentHash = makeContentHash(contentBuffer)
  const parentBFE = bfe.encode(opts.parent || null)
  const tag = Buffer.from([opts.tag])
  const sequence = previous.value.sequence + 1
  const timestamp = +opts.timestamp

  const value = [
    authorBFE,
    parentBFE,
    sequence,
    timestamp,
    previousBFE,
    tag,
    contentBuffer.length,
    contentHash,
  ]

  const encodedValue = bipf.allocAndEncode(value)
  // FIXME: we need ssb-keys to support returning buffer from sign()
  const signature = ssbKeys.sign(opts.keys, opts.hmacKey, encodedValue)
  const sigBuf = _base64ToBuffer(signature)

  return bipf.allocAndEncode([encodedValue, sigBuf, contentBuffer])
}

function _fromNativeMsgJS(nativeMsg) {
  if (_jsMsgValCache.has(nativeMsg)) {
    return _jsMsgValCache.get(nativeMsg)
  }
  const [encodedVal, sigBuf, contentBuf] = extract(nativeMsg)
  const [
    authorBFE,
    parentBFE,
    sequence,
    timestamp,
    previousBFE,
    tag,
    contentLength,
    contentHashBuf,
  ] = bipf.decode(encodedVal)
  const author = bfe.decode(authorBFE)
  const parent = bfe.decode(parentBFE)
  const previous = bfe.decode(previousBFE)
  const content = bipf.decode(contentBuf)
  const contentHash = contentHashBuf
  const signature = sigBuf
  const msgVal = {
    author,
    parent,
    sequence,
    timestamp,
    previous,
    tag,
    content,
    contentHash,
    signature,
  }
  _jsMsgValCache.set(nativeMsg, msgVal)
  return msgVal
}

function _fromNativeMsgBIPF(nativeMsg) {
  if (_bipfMsgValCache.has(nativeMsg)) {
    return _bipfMsgValCache.get(nativeMsg)
  }
  const [encodedVal, sigBuf, contentBuf] = extract(nativeMsg)
  const [
    authorBFE,
    parentBFE,
    sequence,
    timestamp,
    previousBFE,
    tag,
    contentLength,
    contentHash,
  ] = bipf.decode(encodedVal)
  const author = bfe.decode(authorBFE)
  const parent = bfe.decode(parentBFE)
  const previous = bfe.decode(previousBFE)
  const signature = sigBuf
  bipf.markIdempotent(contentBuf)
  const msgVal = {
    author,
    parent,
    sequence,
    timestamp,
    previous,
    content: contentBuf,
    contentHash,
    signature,
    tag,
  }
  const bipfMsg = bipf.allocAndEncode(msgVal)
  _bipfMsgValCache.set(nativeMsg, bipfMsg)
  return bipfMsg
}

function fromNativeMsg(nativeMsg, encoding = 'js') {
  if (encoding === 'js') {
    return _fromNativeMsgJS(nativeMsg)
  } else if (encoding === 'bipf') {
    return _fromNativeMsgBIPF(nativeMsg)
  } else {
    // prettier-ignore
    throw new Error(`Feed format "${name}" does not support encoding "${encoding}"`)
  }
}

function fromDecryptedNativeMsg(plaintextBuf, nativeMsg, encoding = 'js') {
  if (encoding !== 'js') {
    throw new Error('buttwoo-v1 only supports js encoding when decrypting')
  }
  const msgVal = fromNativeMsg(nativeMsg, encoding)
  const content = bipf.decode(plaintextBuf)
  msgVal.content = content
  return msgVal
}

function _toNativeMsgJS(msgVal) {
  const authorBFE = bfe.encode(msgVal.author)
  const parentBFE = bfe.encode(msgVal.parent)
  const sequence = msgVal.sequence
  const timestamp = msgVal.timestamp
  const previousBFE = bfe.encode(msgVal.previous)
  const tag = msgVal.tag
  const contentBuffer = bipf.allocAndEncode(msgVal.content)
  const contentHash = msgVal.contentHash
  const value = [
    authorBFE,
    parentBFE,
    sequence,
    timestamp,
    previousBFE,
    tag,
    contentBuffer.length,
    contentHash,
  ]
  const encodedValue = bipf.allocAndEncode(value)
  const signature = msgVal.signature
  return bipf.allocAndEncode([encodedValue, signature, contentBuffer])
}

function _toNativeMsgBIPF(buffer) {
  let authorBFE, parentBFE, sequence, timestamp, previousBFE
  let tagBuffer, contentBuffer, contentLen, contentHash, sigBuf

  const tag = varint.decode(buffer, 0)
  const len = tag >> BIPF_TAG_SIZE

  for (var c = varint.decode.bytes; c < len; ) {
    const keyStart = c
    var keyTag = varint.decode(buffer, keyStart)
    c += varint.decode.bytes
    c += keyTag >> BIPF_TAG_SIZE
    const valueStart = c
    const valueTag = varint.decode(buffer, valueStart)
    const valueLen = varint.decode.bytes + (valueTag >> BIPF_TAG_SIZE)

    const key = bipf.decode(buffer, keyStart)
    if (key === 'author')
      authorBFE = bfe.encode(bipf.decode(buffer, valueStart))
    else if (key === 'parent')
      parentBFE = bfe.encode(bipf.decode(buffer, valueStart))
    else if (key === 'sequence') sequence = bipf.decode(buffer, valueStart)
    else if (key === 'timestamp') timestamp = bipf.decode(buffer, valueStart)
    else if (key === 'previous')
      previousBFE = bfe.encode(bipf.decode(buffer, valueStart))
    else if (key === 'tag') tagBuffer = bipf.decode(buffer, valueStart)
    else if (key === 'content') {
      if ((valueTag & BIPF_TAG_MASK) === BIPF_STRING_TYPE) {
        contentBuffer = bipf.decode(buffer, valueStart)
        contentLen = _base64ToBuffer(contentBuffer).length
      } else {
        contentBuffer = bipf.pluck(buffer, valueStart)
        contentLen = contentBuffer.length
      }
    } else if (key === 'contentHash')
      contentHash = bipf.decode(buffer, valueStart)
    else if (key === 'signature') sigBuf = bipf.decode(buffer, valueStart)

    c += valueLen
  }

  const value = [
    authorBFE,
    parentBFE,
    sequence,
    timestamp,
    previousBFE,
    tagBuffer,
    contentLen,
    contentHash,
  ]
  const encodedValue = bipf.allocAndEncode(value)
  return bipf.allocAndEncode([encodedValue, sigBuf, contentBuffer])
}

function toNativeMsg(msgVal, encoding = 'js') {
  if (encoding === 'js') {
    return _toNativeMsgJS(msgVal)
  } else if (encoding === 'bipf') {
    return _toNativeMsgBIPF(msgVal)
  } else {
    // prettier-ignore
    throw new Error(`Feed format "${name}" does not support encoding "${encoding}"`)
  }
}

module.exports = {
  // ssb-feed-format:
  name,
  encodings,
  getFeedId,
  getMsgId,
  getSequence,
  isNativeMsg,
  isAuthor,
  toPlaintextBuffer,
  newNativeMsg,
  fromNativeMsg,
  fromDecryptedNativeMsg,
  toNativeMsg,
  validate,
  validateBatch,

  // Not part of ssb-feed-format API:
  validateSync,
  validateBatchSync,
  tags,
}
