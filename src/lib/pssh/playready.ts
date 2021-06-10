import * as crypto from 'crypto'
import * as tools from './tools'
import * as T from '../types'

const DRM_AES_KEYSIZE_128 = 16
const TEST_KEY_SEED = 'XVBovsmzhP9gRIZxWfFta3VVRPzVEWmJsazEJ46I'

interface KeyItem {
  kid: string
  key: string
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
  const kidBuffer = swapEndian(keyId)

  // Truncate if key seed > 30 bytes
  const truncatedKeySeed = Buffer.alloc(30)
  const originalKeySeed = Buffer.from(keySeed, 'base64')
  originalKeySeed.copy(truncatedKeySeed, 0, 0, 30)

  //
  // Create shaA buffer. It is the SHA of the truncatedKeySeed and the keyId
  //
  const shaA = Buffer.concat([truncatedKeySeed, kidBuffer], truncatedKeySeed.length + kidBuffer.length)
  const digestA = crypto.createHash('sha256').update(shaA).digest()

  //
  // Create shaB buffer. It is the SHA of the truncatedKeySeed, the keyId, and
  // the truncatedKeySeed again.
  //
  const shaB = Buffer.concat([truncatedKeySeed, kidBuffer, truncatedKeySeed], (2 * truncatedKeySeed.length) + kidBuffer.length)
  const digestB = crypto.createHash('sha256').update(shaB).digest()

  //
  // Create shaC buffer. It is the SHA of the truncatedKeySeed, the keyId,
  // the truncatedKeySeed again, and the keyId again.
  //
  const shaC = Buffer.concat([truncatedKeySeed, kidBuffer, truncatedKeySeed, kidBuffer], (2 * truncatedKeySeed.length) + (2 * kidBuffer.length))
  const digestC = crypto.createHash('sha256').update(shaC).digest()

  // Calculate Content Key
  const keyBuffer = Buffer.alloc(DRM_AES_KEYSIZE_128)
  for (let i = 0; i < DRM_AES_KEYSIZE_128; i++) {
    const value = digestA[i] ^ digestA[i + DRM_AES_KEYSIZE_128] ^ digestB[i] ^ digestB[i + DRM_AES_KEYSIZE_128] ^ digestC[i] ^ digestC[i + DRM_AES_KEYSIZE_128]
    keyBuffer[i] = value
  }

  // Calculate checksum
  const cipher = crypto.createCipheriv('aes-128-ecb', keyBuffer, '').setAutoPadding(false)
  const checksum = cipher.update(kidBuffer).slice(0, 8).toString('base64')

  return {
    kid: kidBuffer.toString('base64'),
    key: swapEndian(keyBuffer.toString('hex')).toString('base64'),
    checksum
  }
}

const constructProXML4 = (keyPair: T.KeyPair, licenseUrl: string, keySeed: string, checksum: boolean = true): string => {
  const key = encodeKey(keyPair, keySeed)

  const xmlArray = ['<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.0.0.0">']

  xmlArray.push('<DATA>')
  xmlArray.push('<PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO>')
  xmlArray.push(`<KID>${key.kid}</KID>`)

  if (checksum) {
    xmlArray.push(`<CHECKSUM>${key.checksum}</CHECKSUM>`)
  }

  if (licenseUrl && licenseUrl !== '') {
    xmlArray.push(`<LA_URL>${licenseUrl}</LA_URL>`)
  }
  xmlArray.push('<CUSTOMATTRIBUTES>')
  xmlArray.push('<IIS_DRM_VERSION>8.0.1906.32</IIS_DRM_VERSION>')
  xmlArray.push('</CUSTOMATTRIBUTES>')
  xmlArray.push('</DATA>')
  xmlArray.push('</WRMHEADER>')

  return xmlArray.join('')
}

const constructProXML = (keyPairs: T.KeyPair[], licenseUrl: string, keySeed: string, checksum: boolean = true): string => {
  const keyIds = keyPairs.map((k) => {
    return encodeKey(k, keySeed)
  })
  const xmlArray = ['<?xml version="1.0" encoding="UTF-8"?>']
  xmlArray.push('<WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.2.0.0">')
  xmlArray.push('<DATA>')
  xmlArray.push('<PROTECTINFO><KIDS>')
  // Construct Key
  keyIds.forEach((key) => {
    if (!checksum) {
      xmlArray.push(`<KID ALGID="AESCTR" VALUE="${key.kid}">`)
    } else {
      xmlArray.push(`<KID ALGID="AESCTR" CHECKSUM="${key.checksum}" VALUE="${key.kid}">`)
    }
    xmlArray.push('</KID>')
  })
  xmlArray.push('</KIDS></PROTECTINFO>')
  // Construct License URL
  if (licenseUrl && licenseUrl !== '') {
    xmlArray.push('<LA_URL>')
    xmlArray.push(`${licenseUrl}?cfg=`)
    for (let i = 0; i < keyIds.length; i++) {
      // TODO: Options to pass predefined contentkey
      xmlArray.push(`(kid:${keyIds[i].kid})`)
      if (i < keyPairs.length - 1) {
        xmlArray.push(',')
      }
    }
    xmlArray.push('</LA_URL>')
  }
  xmlArray.push('<CUSTOMATTRIBUTES>')
  xmlArray.push('<IIS_DRM_VERSION>8.0.1906.32</IIS_DRM_VERSION>')
  xmlArray.push('</CUSTOMATTRIBUTES>')
  xmlArray.push('</DATA>')
  xmlArray.push('</WRMHEADER>')
  return xmlArray.join('')
}

const getPsshData = (request: T.PlayReadyDataEncodeConfig): string => {
  const licenseUrl = request.licenseUrl || ''
  const keySeed = request.keySeed || ''
  const emptyKey = { key: '', kid: '' }
  const xmlData = request.compatibilityMode === true ? constructProXML4(request.keyPairs ? request.keyPairs[0] : emptyKey, licenseUrl, keySeed, request.checksum) : constructProXML(request.keyPairs ? request.keyPairs : [], licenseUrl, keySeed, request.checksum)

  // Play Ready Object Header
  const headerBytes = Buffer.from(xmlData, 'utf16le')
  const headerLength = headerBytes.length
  const proLength = headerLength + 10
  const recordCount = 1
  const recordType = 1

  // Play Ready Object (PRO)
  const data = Buffer.alloc(proLength)
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
    keyIds: request.keyPairs ? request.keyPairs.map((k) => k.kid) : [],
    data: data
  }
  const psshHeader = tools.getPsshHeader(requestData)
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

export const encodeKey = (keyPair: T.KeyPair, keySeed: string = ''): KeyItem => {
  if (keySeed && keySeed.length) {
    return generateContentKey(keyPair.kid, keySeed)
  }

  const kidBuffer = swapEndian(keyPair.kid)

  // Calculate the checksum with provided key
  const keyBuffer = Buffer.from(keyPair.key, 'hex')
  const cipher = crypto.createCipheriv('aes-128-ecb', keyBuffer, '').setAutoPadding(false)
  const checksum = cipher.update(kidBuffer).slice(0, 8).toString('base64')

  return {
    kid: kidBuffer.toString('base64'),
    key: swapEndian(keyPair.key).toString('base64'),
    checksum
  }
}
