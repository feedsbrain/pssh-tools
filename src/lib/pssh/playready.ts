import * as crypto from 'crypto'
import * as tools from './tools'
import * as T from '../types'

const DRM_AES_KEYSIZE_128 = 16
const TEST_KEY_SEED = 'XVBovsmzhP9gRIZxWfFta3VVRPzVEWmJsazEJ46I'

interface KeyItem {
  kid: string
  checksum: string
}

const swapEndian = (keyId: string): Buffer => {
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
const generateContentKey = (keyId: string, keySeed: string = TEST_KEY_SEED): KeyItem => {
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
  for (let i = 0; i < DRM_AES_KEYSIZE_128; i++) {
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

const constructProXML4 = (keyId: string, licenseUrl: string, keySeed: string): string => {
  let key = keySeed && keySeed.length ? generateContentKey(keyId, keySeed) : encodeKey(keyId)

  let xmlArray = ['<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.0.0.0">']
  xmlArray.push('<DATA>')
  xmlArray.push('<PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO>')
  xmlArray.push(`<KID>${key.kid}</KID><CHECKSUM>${key.checksum}</CHECKSUM>`)
  if (licenseUrl && licenseUrl.length) {
    xmlArray.push(`<LA_URL>${licenseUrl}</LA_URL>`)
  }
  xmlArray.push('</DATA>')
  xmlArray.push('</WRMHEADER>')

  return xmlArray.join('')
}

const constructProXML = (keyIds: string[], licenseUrl: string, keySeed: string): string => {
  let contentKeys = keyIds.map((k) => {
    return keySeed && keySeed.length ? generateContentKey(k, keySeed) : encodeKey(k)
  })
  let xmlArray = ['<?xml version="1.0" encoding="UTF-8"?>']
  xmlArray.push('<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.2.0.0">')
  xmlArray.push('<DATA>')
  xmlArray.push('<PROTECTINFO><KIDS>')
  // Construct Key
  contentKeys.forEach((key) => {
    xmlArray.push(`<KID ALGID="AESCTR" CHECKSUM="${key.checksum}" VALUE="${key.kid}">`)
    xmlArray.push('</KID>')
  })
  xmlArray.push('</KIDS></PROTECTINFO>')
  // Construct License URL
  if (licenseUrl) {
    xmlArray.push('<LA_URL>')
    xmlArray.push(`${licenseUrl}?cfg=`)
    for (let i = 0; i < contentKeys.length; i++) {
      // TODO: Options to pass predefined contentkey
      xmlArray.push(`(kid:${contentKeys[i].kid})`)
      if (i < keyIds.length - 1) {
        xmlArray.push(',')
      }
    }
    xmlArray.push('</LA_URL>')
  }

  xmlArray.push('</DATA>')
  xmlArray.push('</WRMHEADER>')
  return xmlArray.join('')
}

const getPsshData = (request: T.PlayReadyDataEncodeConfig): string => {
  const licenseUrl = request.licenseUrl || ''
  const keySeed = request.keySeed || ''
  const xmlData = request.compatibilityMode === true ? constructProXML4(request.keyIds ? request.keyIds[0] : '', licenseUrl, keySeed) : constructProXML(request.keyIds ? request.keyIds : [], licenseUrl, keySeed)

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

const getPsshBox = (request: T.PlayReadyDataEncodeConfig) => {
  // data
  const data = getPsshData(request)
  const requestData: T.HeaderConfig = {
    systemId: tools.system.PLAYREADY.id,
    keyIds: request.keyIds,
    data: data
  }
  let psshHeader = tools.getPsshHeader(requestData)
  return psshHeader
}

export const encodePssh = (request: T.PlayReadyEncodeConfig) => {
  if (request.dataOnly) {
    return getPsshData(request)
  }
  return getPsshBox(request)
}

export const decodeData = (data: string) => {
  return tools.decodePsshData(tools.system.PLAYREADY.name, data)
}

export const decodeKey = (keyData: string) => {
  const keyBuffer = Buffer.from(keyData, 'base64')
  return swapEndian(keyBuffer.toString('hex')).toString('hex')
}

export const encodeKey = (keyData: string): KeyItem => {
  const keyBuffer = swapEndian(keyData)

  const cipher = crypto.createCipheriv('aes-128-ecb', keyBuffer, '').setAutoPadding(false)
  const checksum = cipher.update(keyBuffer).slice(0, 8).toString('base64')

  return {
    kid: keyBuffer.toString('base64'),
    checksum
  }
}
