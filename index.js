const bipf = require('bipf')
const bfe = require('ssb-bfe')
const blake3 = require('blake3')
const ssbKeys = require('ssb-keys')
const varint = require('varint')

function extractData(b) {
  const [encodedValue, signature, contentBipf] = bipf.decode(b, 0)
  const [authorBFE, parentBFE, sequence, timestamp, previousBFE, tag,
         contentSize, contentHash] = bipf.decode(encodedValue, 0)

  return [
    [encodedValue, signature, contentBipf],
    [authorBFE, parentBFE, sequence, timestamp, previousBFE, tag,
     contentSize, contentHash]
  ]
}

const authorLength = bipf.encodingLength('author')
const parentLength = bipf.encodingLength('parent')
const sequenceLength = bipf.encodingLength('sequence')
const timestampLength = bipf.encodingLength('timestamp')
const previousLength = bipf.encodingLength('previous')
const signatureLength = bipf.encodingLength('signature')
const tagLength = bipf.encodingLength('tag')
const contentLength = bipf.encodingLength('content')
const contentHashLength = bipf.encodingLength('contentHash')
const keyLength = bipf.encodingLength('key')
const valueLength = bipf.encodingLength('value')

const TAG_SIZE = 3
const TAG_MASK = 7

function varintLength(len) {
  return varint.encodingLength(len << TAG_SIZE) + len
}

function butt2ToBipf(data, msgKeyBFE) {
  const [butt2, signature, contentBipf] = data[0]
  const [authorBFE, parentBFE, sequence, timestamp,
         previousBFE, tag, contentLen, contentHash] = data[1]

  const author = bfe.decode(authorBFE)
  const parent = bfe.decode(parentBFE)
  const previous = bfe.decode(previousBFE)
  const msgKey = bfe.decode(msgKeyBFE)

  // FIXME: encode signature?

  let valueObjSize = authorLength
  valueObjSize += bipf.encodingLength(author)
  valueObjSize += parentLength
  valueObjSize += bipf.encodingLength(parent)
  valueObjSize += sequenceLength
  valueObjSize += bipf.encodingLength(sequence)
  valueObjSize += timestampLength
  valueObjSize += bipf.encodingLength(timestamp)
  valueObjSize += previousLength
  valueObjSize += bipf.encodingLength(previous)
  valueObjSize += contentLength
  valueObjSize += contentBipf.length
  valueObjSize += signatureLength
  valueObjSize += bipf.encodingLength(signature)
  valueObjSize += tagLength
  valueObjSize += bipf.encodingLength(tag)
  valueObjSize += contentHashLength
  valueObjSize += bipf.encodingLength(contentHash)
  
  let kvtObjSize = keyLength
  kvtObjSize += bipf.encodingLength(msgKey)
  kvtObjSize += valueLength
  kvtObjSize += varintLength(valueObjSize)

  const totalKVTObjSize = varintLength(kvtObjSize)
  const kvtBuffer = Buffer.allocUnsafe(totalKVTObjSize)
  let p = 0

  // write TL
  varint.encode((kvtObjSize << TAG_SIZE) | bipf.types.object,
                kvtBuffer, p)
  p += varint.encode.bytes

  // write V
  p += bipf.encode('key', kvtBuffer, p)
  p += bipf.encode(msgKey, kvtBuffer, p)

  p += bipf.encode('value', kvtBuffer, p)

  // write TL
  varint.encode((valueObjSize << TAG_SIZE) | bipf.types.object,
                kvtBuffer, p)
  p += varint.encode.bytes

  // write V
  p += bipf.encode('author', kvtBuffer, p)
  p += bipf.encode(author, kvtBuffer, p)
  p += bipf.encode('parent', kvtBuffer, p)
  p += bipf.encode(parent, kvtBuffer, p)
  p += bipf.encode('sequence', kvtBuffer, p)
  p += bipf.encode(sequence, kvtBuffer, p)
  p += bipf.encode('timestamp', kvtBuffer, p)
  p += bipf.encode(timestamp, kvtBuffer, p)
  p += bipf.encode('previous', kvtBuffer, p)
  p += bipf.encode(previous, kvtBuffer, p)
  p += bipf.encode('content', kvtBuffer, p)
  contentBipf.copy(kvtBuffer, p, 0, contentBipf.length)
  p += contentBipf.length
  p += bipf.encode('contentHash', kvtBuffer, p)
  p += bipf.encode(contentHash, kvtBuffer, p)
  p += bipf.encode('signature', kvtBuffer, p)
  p += bipf.encode(signature, kvtBuffer, p)
  p += bipf.encode('tag', kvtBuffer, p)
  p += bipf.encode(tag, kvtBuffer, p)
  
  //console.log("msg", bipf.decode(kvtBuffer, 0))
  return kvtBuffer
}

function authorToBFE(author) {
  return Buffer.concat([
    bfe.toTF('feed', 'butt2-v1'),
    base64ToBuffer(author)
  ])
}

function msgIdToBFE(buffer) {
  return Buffer.concat([
    bfe.toTF('message', 'butt2-v1'),
    buffer
  ])
}

function hashToBFE(buffer) {
  return Buffer.concat([
    bfe.toTF('blob', 'butt2-v1'),
    buffer
  ])
}
function signatureToBFE(signature) {
  return Buffer.concat([
    bfe.toTF('signature', 'butt2-v1'),
    base64ToBuffer(signature)
  ])
}

const tags = {
  SSB_FEED: Buffer.from([0]),
  SUB_FEED: Buffer.from([1]),
  END_OF_FEED: Buffer.from([2])
}

function base64ToBuffer(str) {
  var i = str.indexOf(".")
  return Buffer.from(str.substring(0, i), "base64")
}

// just for debugging
function msgValToButt2(msgVal) {
  // content as bipf
  const contentBipf = bipf.allocAndEncode(msgVal.content)
  const contentHash = hashToBFE(blake3.hash(contentBipf))

  const authorBFE = bfe.encode(msgVal.author)
  const parentBFE = bfe.encode(msgVal.parent)
  const previousBFE = bfe.encode(msgVal.previous)
  // FIXME: decode signature?

  const value = [
    authorBFE,
    parentBFE,
    msgVal.sequence,
    parseInt(msgVal.timestamp),
    previousBFE,
    msgVal.tag,
    contentBipf.length,
    contentHash
  ]

  // encoded for signature
  const encodedValue = bipf.allocAndEncode(value)

  return bipf.allocAndEncode([encodedValue, msgVal.signature, contentBipf])
}

const BIPF_VALUE = bipf.allocAndEncode('value')

// buffer is kvt
function bipfToButt2(buffer) {
  const pValue = bipf.seekKey2(buffer, 0, BIPF_VALUE, 0)

  let authorBFE, parentBFE, sequence, timestamp, previousBFE
  let tagBuffer, contentBipf, contentHash, signatureBuffer

  const tag = varint.decode(buffer, pValue)
  const len = tag >> TAG_SIZE

  for (var c = varint.decode.bytes; c < len; ) {
    const keyStart = pValue + c
    var keyTag = varint.decode(buffer, keyStart)
    c += varint.decode.bytes
    c += keyTag >> TAG_SIZE
    const valueStart = pValue + c
    const valueTag = varint.decode(buffer, valueStart)
    const valueLen = varint.decode.bytes + (valueTag >> TAG_SIZE)

    const key = bipf.decode(buffer, keyStart)
    if (key === 'author')
      authorBFE = bfe.encode(bipf.decode(buffer, valueStart))
    else if (key === 'parent')
      parentBFE = bfe.encode(bipf.decode(buffer, valueStart))
    else if (key === 'sequence')
      sequence = bipf.decode(buffer, valueStart)
    else if (key === 'timestamp')
      timestamp = bipf.decode(buffer, valueStart)
    else if (key === 'previous')
      previousBFE = bfe.encode(bipf.decode(buffer, valueStart))
    else if (key === 'tag')
      tagBuffer = bipf.decode(buffer, valueStart)
    else if (key === 'content')
      contentBipf = buffer.slice(valueStart, valueStart + valueLen)
    else if (key === 'contentHash')
      contentHash = bipf.decode(buffer, valueStart)
    else if (key === 'signature')
      signatureBuffer = bipf.decode(buffer, valueStart)

    c += valueLen
  }

  const value = [
    authorBFE,
    parentBFE,
    sequence,
    timestamp,
    previousBFE,
    tagBuffer,
    contentBipf.length,
    contentHash
  ]

  // encoded for signature
  const encodedValue = bipf.allocAndEncode(value)

  return bipf.allocAndEncode([encodedValue, signatureBuffer, contentBipf])
}

const BFE_NIL = Buffer.from([6,2])

// FIXME: boxer
function encodeNew(content, keys, parentBFE, sequence, previousBFE, timestamp,
                   tag, hmacKey) {
  // content as bipf
  const contentBipf = bipf.allocAndEncode(content)
  const contentHash = hashToBFE(blake3.hash(contentBipf))

  const authorBFE = authorToBFE(keys.public)

  const value = [
    authorBFE,
    parentBFE === null ? BFE_NIL : parentBFE,
    sequence,
    parseInt(timestamp),
    previousBFE === null ? BFE_NIL : previousBFE,
    tag,
    contentBipf.length,
    contentHash
  ]

  const encodedValue = bipf.allocAndEncode(value)
  const signature = signatureToBFE(ssbKeys.sign(keys, hmacKey, encodedValue))

  const valueSignature = Buffer.concat([encodedValue, signature])
  const msgKeyBFE = msgIdToBFE(blake3.hash(valueSignature))

  return [
    msgKeyBFE,
    bipf.allocAndEncode([encodedValue, signature, contentBipf])
  ]
}

function validateBase(data, previousData, previousKeyBFE) {
  const [encodedValue, signature, contentBipf] = data[0]
  const [authorBFE, parentBFE, sequence, timestamp, previousBFE, tag,
         contentSize, contentHash] = data[1]

  if (contentBipf.length !== contentSize)
    return new Error('Content size does not match content')

  const testedContentHash = hashToBFE(blake3.hash(contentBipf))
  if (Buffer.compare(testedContentHash, contentHash) !== 0)
    return new Error('Content hash does not match content')

  if (typeof timestamp !== 'number' || isNaN(timestamp) || !isFinite(timestamp))
    return new Error(`invalid message: timestamp is "${timestamp}", expected a JavaScript number`)

  // FIXME: check if correct BFE types!
  // FIXME: check length of content

  if (previousData !== null) {
    const [encodedValuePrev, signaturePrev] = previousData[0]
    const [authorBFEPrev, parentBFEPrev, sequencePrev, timestampPrev,
           previousBFEPrev, tagPrev] = previousData[1]

    if (Buffer.compare(authorBFE, authorBFEPrev) !== 0)
      return new Error('Author does not match previous message')

    if (Buffer.compare(parentBFE, parentBFEPrev) !== 0)
      return new Error('Parent does not match previous message')

    if (sequence !== sequencePrev + 1)
      return new Error('Sequence must increase')
    
    if (timestamp <= timestampPrev)
      return new Error('Timestamp must increase')

    if (Buffer.compare(previousBFE, previousKeyBFE) !== 0)
      return new Error('Previous does not match key of previous message')

    if (Buffer.compare(tagPrev, tags.END_OF_FEED) === 0)
      return new Error('Feed already terminated')
  } else {
    if (sequence !== 1)
      return new Error('Sequence must be 1 for first message')

    if (Buffer.compare(previousBFE, Buffer.from([6,2])) !== 0)
      return new Error('Previous must be nil for first message')
  }
}

function validateSignature(data, hmacKey) {
  const [encodedValue, signature] = data[0]
  const [authorBFE] = data[1]
  const key = { public: authorBFE.slice(2), curve: 'ed25519' }

  if (!ssbKeys.verify(key, signature.slice(2), hmacKey, encodedValue))
    return new Error('Signature does not match encoded value')
}

function validateSingle(data, previousData, previousKeyBFE, hmacKey) {
  const err = validateBase(data, previousData, previousKeyBFE)
  if (err) return err

  const errS = validateSignature(data, null, hmacKey)
  if (errS) return errS
}

function validateBatch(batch, previousData, previousKeyBFE, hmacKey) {
  const keys = []
  for (let i = 0; i < batch.length; ++i) {
    const data = batch[i]
    const err = validateBase(data, previousData, previousKeyBFE)
    if (err) return err

    previousData = data
    previousKeyBFE = hash(data)

    keys.push(previousKeyBFE)
  }

  // FIXME: maybe some random element?
  const data = batch[batch.length - 1]
  const err = validateSignature(data, hmacKey)
  if (err) return err

  return keys
}

function hash(data) {
  const [encodedValue, signature] = data[0]
  return msgIdToBFE(blake3.hash(Buffer.concat([encodedValue, signature])))
}

const ARRAY = 4 // 100
const BUFFER = 1 // 001

function extractValueElement(buffer, valueIndex) {
  let p = 0

  let tag = varint.decode(buffer, p)
  let len = tag >> TAG_SIZE
  let type = tag & TAG_MASK

  if (type !== ARRAY) return

  p += varint.decode.bytes

  // encoded value is encoded as a buffer
  tag = varint.decode(buffer, p)
  len = tag >> TAG_SIZE
  type = tag & TAG_MASK

  if (type !== BUFFER) return

  p += varint.decode.bytes

  tag = varint.decode(buffer, p)
  len = tag >> TAG_SIZE
  type = tag & TAG_MASK

  if (type !== ARRAY) return

  let i = 0
  for (var c = varint.decode.bytes; c < len; i++) {
    if (i === valueIndex)
      return bipf.decode(buffer, p + c)

    const arrayTag = varint.decode(buffer, p + c)
    c += varint.decode.bytes + (arrayTag >> TAG_SIZE)
  }
}

function extractAuthor(buffer) {
  return extractValueElement(buffer, 0)
}

function extractParent(buffer) {
  return extractValueElement(buffer, 1)
}

function extractSequence(buffer) {
  return extractValueElement(buffer, 2)
}

module.exports = {
  extractData,

  butt2ToBipf, // network -> db
  bipfToButt2, // db -> network

  msgValToButt2, // db -> network (slow)

  // ebt+db2 helpers
  extractAuthor,
  extractParent,
  extractSequence,

  // FIXME: we might need one that maps well with publish
  encodeNew, // local -> db
  tags,

  validateSingle,
  validateBatch,

  hash
}
