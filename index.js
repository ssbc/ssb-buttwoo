const bipf = require('bipf')
const bfe = require('ssb-bfe')
const blake3 = require('blake3')
const ssbKeys = require('ssb-keys')
const varint = require('varint')

function extractData(b) {
  const [valueSignature, contentBipf] = bipf.decode(b, 0)
  const [encodedValue, signatures] = bipf.decode(valueSignature, 0)
  const [authorBFE, sequence, timestamp, backlinkBFE, tag,
         contentSize, contentHash] = bipf.decode(encodedValue, 0)

  // 3 layers
  return [
    [valueSignature, contentBipf],
    [encodedValue, signatures],
    [authorBFE, sequence, timestamp, backlinkBFE, tag, contentSize, contentHash]
  ]
}

const authorLength = bipf.encodingLength('author')
const sequenceLength = bipf.encodingLength('sequence')
const timestampLength = bipf.encodingLength('timestamp')
const previousLength = bipf.encodingLength('previous')
const signaturesLength = bipf.encodingLength('signatures')
const tagLength = bipf.encodingLength('tag')
const contentLength = bipf.encodingLength('content')
const keyLength = bipf.encodingLength('key')
const valueLength = bipf.encodingLength('value')

const TAG_SIZE = 3

function varintLength(len) {
  return varint.encodingLength(len << TAG_SIZE) + len
}

function butt2ToBipf(data, msgKeyBFE) {
  const [valueSignature, contentBipf] = data[0]
  const [encodedValue, signatures] = data[1]
  const [authorBFE, sequence, timestamp, backlinkBFE, tag] = data[2]

  const author = bfe.decode(authorBFE)
  const backlink = bfe.decode(backlinkBFE)
  const msgKey = bfe.decode(msgKeyBFE)

  let valueObjSize = authorLength
  valueObjSize += bipf.encodingLength(author)
  valueObjSize += sequenceLength
  valueObjSize += bipf.encodingLength(sequence)
  valueObjSize += timestampLength
  valueObjSize += bipf.encodingLength(timestamp)
  valueObjSize += previousLength
  valueObjSize += bipf.encodingLength(backlink)
  valueObjSize += contentLength
  valueObjSize += contentBipf.length
  valueObjSize += signaturesLength
  valueObjSize += bipf.encodingLength(signatures)
  valueObjSize += tagLength
  valueObjSize += bipf.encodingLength(tag)
  
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
  p += bipf.encode('sequence', kvtBuffer, p)
  p += bipf.encode(sequence, kvtBuffer, p)
  p += bipf.encode('timestamp', kvtBuffer, p)
  p += bipf.encode(timestamp, kvtBuffer, p)
  p += bipf.encode('previous', kvtBuffer, p)
  p += bipf.encode(backlink, kvtBuffer, p)
  p += bipf.encode('content', kvtBuffer, p)
  contentBipf.copy(kvtBuffer, p, 0, contentBipf.length)
  p += contentBipf.length
  p += bipf.encode('signatures', kvtBuffer, p)
  p += bipf.encode(signatures, kvtBuffer, p)
  p += bipf.encode('tag', kvtBuffer, p)
  p += bipf.encode(tag, kvtBuffer, p)
  
  //console.log("msg", bipf.decode(kvtBuffer, 0))
  return kvtBuffer
}

function ed25519AuthorToButt2BFE(author) {
  return Buffer.concat([
    bfe.toTF('feed', 'butt2-v1'),
    rawSignature(author)
  ])
}

function encodeMsgIdToBFE(buffer) {
  return Buffer.concat([
    bfe.toTF('message', 'butt2-v1'),
    buffer
  ])
}

const tag = {
  SSB_FEED: Buffer.from([0]),
  END_OF_FEED: Buffer.from([1])
}

function rawSignature(str) {
  var i = str.indexOf(".")
  return Buffer.from(str.substring(0, i), "base64")
}

function msgValToButt2(msgVal) {
  // content as bipf
  const contentBipf = bipf.allocAndEncode(msgVal.content)
  const contentHash = encodeMsgIdToBFE(blake3.hash(contentBipf))

  const backlinkBFE = bfe.encode(msgVal.previous)
  const authorBFE = bfe.encode(msgVal.author)

  const value = [
    authorBFE,
    msgVal.sequence,
    parseInt(msgVal.timestamp),
    backlinkBFE,
    msgVal.tag,
    contentBipf.length,
    contentHash
  ]

  // encoded for signatures
  const encodedValue = bipf.allocAndEncode(value)

  // encoded for hash
  const valueSignature = bipf.allocAndEncode([encodedValue, msgVal.signatures])

  return bipf.allocAndEncode([valueSignature, contentBipf])
}

// FIXME: boxer
// FIXME: end-of-feed?
// FIXME: backlinks if needed for signature
function encodeNew(content, keys, sequence, backlinkBFE, timestamp, hmacKey) {
  // content as bipf
  const contentBipf = bipf.allocAndEncode(content)
  const contentHash = encodeMsgIdToBFE(blake3.hash(contentBipf))

  // FIXME: we need to figure out what we do with the key
  const authorBFE = ed25519AuthorToButt2BFE(keys.public)

  const value = [
    authorBFE,
    sequence,
    parseInt(timestamp),
    backlinkBFE,
    tag.SSB_FEED,
    contentBipf.length,
    contentHash
  ]

  // encoded for signatures
  const encodedValue = bipf.allocAndEncode(value)

  const signatures = {}

  const signature = ssbKeys.sign(keys, hmacKey, encodedValue)
  signatures[sequence] = rawSignature(signature)

  // encoded for hash
  const valueSignature = bipf.allocAndEncode([encodedValue, signatures])
  const msgKeyBFE = encodeMsgIdToBFE(blake3.hash(valueSignature))

  return [
    msgKeyBFE,
    bipf.allocAndEncode([valueSignature, contentBipf])
  ]
}

function validateBase(data, previousData, previousKeyBFE) {
  const [valueSignature, contentBipf] = data[0]
  const [encodedValue, signatures] = data[1]
  const [authorBFE, sequence, timestamp, backlinkBFE, tag,
         contentSize, contentHash] = data[2]

  if (contentBipf.length !== contentSize)
    return 'Content size does not match content'

  const testedContentHash = encodeMsgIdToBFE(blake3.hash(contentBipf))
  if (Buffer.compare(testedContentHash, contentHash) !== 0)
    return 'Content hash does not match content'

  if (typeof timestamp !== 'number' || isNaN(timestamp) || !isFinite(timestamp))
    return `invalid message: timestamp is "${timestamp}", expected a JavaScript number`

  // FIXME: check if correct BFE types!
  // FIXME: check length of content

  if (previousData !== null) {
    const [valueSignature] = previousData[0]
    const [encodedValuePrev] = previousData[1]
    const [authorBFEPrev, sequencePrev, timestampPrev,
           backlinkBFEPrev, tagPrev] = previousData[2]

    if (Buffer.compare(authorBFE, authorBFEPrev) !== 0)
      return 'Author does not match previous message'

    if (sequence !== sequencePrev + 1)
      return 'Sequence must increase'
    
    if (timestamp <= timestampPrev)
      return 'Timestamp must increase'

    if (Buffer.compare(backlinkBFE, previousKeyBFE) !== 0)
      return 'Backlink does not match key of previous message'

    if (Buffer.compare(tagPrev, END_OF_FEED) === 0)
      return 'Feed already terminated'
  } else {
    if (sequence !== 1)
      return 'Sequence must be 1 for first message'

    if (Buffer.compare(backlinkBFE, Buffer.from([6,2])) !== 0)
      return 'Backlink must be nil for first message'
  }

  return encodeMsgIdToBFE(blake3.hash(valueSignature))
}

function validateSignature(data, hmacKey) {
  const [valueSignature] = data[0]
  const [encodedValue, signatures] = data[1]
  const [authorBFE, sequence, timestamp, backlink] = data[2]
  const key = { public: authorBFE.slice(2), curve: 'ed25519' }

  if (!ssbKeys.verify(key, signatures[sequence], hmacKey, encodedValue)) {
    console.log("signature does not match")
    return 'Signature does not match hash of encoded value'
  }
}

function validateSingle(data, previousData, previousKeyBFE, hmacKey) {
  const msgKeyBFEorErr = validateBase(data, previousData, previousKeyBFE)
  // FIXME: error handling
  const err = validateSignature(data, hmacKey)
  if (err) return err
  else return msgKeyBFEorErr
}

function validateBatch(batch, previousData, previousKeyBFE) {
  const keys = []
  for (data of batch) {
    // FIXME: update previous
    keys.push(validateBase(data, previousData, previousKeyBFE))
    // FIXME: error handling
    // FIXME: figure out if we can use batch signatures
    validateSignature(data)
  }
  return keys
}

module.exports = {
  extractData,

  butt2ToBipf, // network -> db
  msgValToButt2, // db -> network
  //bipfToButt2, // we need this, a lot more efficient

  encodeNew, // local -> db

  validateSingle,
  validateBatch,
}
