const crypto = require('crypto')

const DRM_AES_KEYSIZE_128 = 16

const swapEndian = (keyId) => {
  // Microsoft GUID endianness
  const keyIdBytes = Buffer.from(keyId, 'hex')
  const keyIdBuffer = Buffer.concat(
    [
      keyIdBytes.slice(0, 4).swap32(),
      keyIdBytes.slice(4, 6).swap16(),
      keyIdBytes.slice(6, 8).swap16(),
      keyIdBytes.slice(8, 16)
    ],
    DRM_AES_KEYSIZE_128
  )
  return keyIdBuffer
}

// From: http://download.microsoft.com/download/2/3/8/238F67D9-1B8B-48D3-AB83-9C00112268B2/PlayReady%20Header%20Object%202015-08-13-FINAL-CL.PDF
const generateContentKey = (keyId, keySeed) => {
  // Microsoft GUID endianness
  const keyIdBuffer = swapEndian(keyId)

  // Truncate if key seed > 30 bytes
  const truncatedKeySeed = Buffer.alloc(30)
  const originalKeySeed = Buffer.from(keySeed, 'base64')
  originalKeySeed.copy(truncatedKeySeed, 0, 0, 30)

  //
  // Create shaA buffer. It is the SHA of the truncatedKeySeed and the keyId
  //
  const shaA = Buffer.concat([truncatedKeySeed, keyIdBuffer], truncatedKeySeed.length + keyIdBuffer.length)
  const digestA = crypto.createHash('sha256').update(shaA).digest()

  //
  // Create shaB buffer. It is the SHA of the truncatedKeySeed, the keyId, and
  // the truncatedKeySeed again.
  //
  const shaB = Buffer.concat([truncatedKeySeed, keyIdBuffer, truncatedKeySeed], (2 * truncatedKeySeed.length) + keyIdBuffer.length)
  const digestB = crypto.createHash('sha256').update(shaB).digest()

  //
  // Create shaC buffer. It is the SHA of the truncatedKeySeed, the keyId,
  // the truncatedKeySeed again, and the keyId again.
  //
  const shaC = Buffer.concat([truncatedKeySeed, keyIdBuffer, truncatedKeySeed, keyIdBuffer], (2 * truncatedKeySeed.length) + (2 * keyIdBuffer.length))
  const digestC = crypto.createHash('sha256').update(shaC).digest()

  // Calculate Content Key
  const contentBuffer = Buffer.alloc(DRM_AES_KEYSIZE_128)
  for (var i = 0; i < DRM_AES_KEYSIZE_128; i++) {
    let value = digestA[i] ^ digestA[i + DRM_AES_KEYSIZE_128] ^ digestB[i] ^ digestB[i + DRM_AES_KEYSIZE_128] ^ digestC[i] ^ digestC[i + DRM_AES_KEYSIZE_128]
    contentBuffer[i] = value
  }
  const kid = contentBuffer.toString('base64')

  // Calculate checksum
  const cipher = crypto.createCipheriv('aes-128-ecb', contentBuffer, '').setAutoPadding(false)
  const checksum = cipher.update(keyIdBuffer).slice(0, 8).toString('base64')

  return {
    kid,
    checksum
  }
}

const constructProXML = (licenseUrl, kids, keySeed) => {
  let contentKeys = kids.map((key) => {
    return generateContentKey(key.kid, keySeed)
  })
  let xmlArray = ['<?xml version="1.0" encoding="UTF-8"?>']
  xmlArray.push('<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.2.0.0">')
  xmlArray.push('<DATA>')
  xmlArray.push('<PROTECTINFO><KIDS>')
  contentKeys.forEach((key) => {
    xmlArray.push(`<KID ALGID="AESCTR" CHECKSUM="${key.checksum}" VALUE="${key.kid}">`)
    xmlArray.push('</KID>')
  })
  xmlArray.push('</KIDS></PROTECTINFO>')
  xmlArray.push('<LA_URL>')
  xmlArray.push(`${licenseUrl}?cfg=`)
  for (let i = 0; i < contentKeys.length; i++) {
    xmlArray.push(`(kid:${contentKeys[i].kid},contentkey:${kids[i].key})`)
    if (i < kids.length - 1) {
      xmlArray.push(',')
    }
  }
  xmlArray.push('</LA_URL>')
  xmlArray.push('</DATA>')
  xmlArray.push('</WRMHEADER>')
  return xmlArray.join('')
}

const getPsshData = (keyIds) => {
  const xmlData = constructProXML(keyIds)

  // Play Ready Object Header
  let headerBytes = Buffer.from(xmlData, 'utf16le')
  let headerLength = headerBytes.length
  let proLength = headerLength + 10
  let recordCount = 1
  let recordType = 1

  // Play Ready Object (PRO)
  let data = Buffer.alloc(proLength)
  data.writeInt32LE(proLength, 0)
  data.writeInt16LE(recordCount, 4)
  data.writeInt16LE(recordType, 6)
  data.writeInt16LE(headerLength, 8)
  data.write(xmlData, 10, proLength, 'utf16le')

  // data
  return Buffer.from(data).toString('base64')
}

const generatePssh = ({ keyIds = [], dataOnly = false }) => {
  if (dataOnly) {
    return getPsshData({
      keyIds: keyIds
    })
  }
  return null
}

module.exports = {
  generatePssh
}
