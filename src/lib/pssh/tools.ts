import * as path from 'path'
import * as protobuf from 'protobufjs'
import { HeaderConfig, PlayReadyData, WidevineData, DecodeResult } from '../types'

export const system = {
  WIDEVINE: { id: 'EDEF8BA979D64ACEA3C827DCD51D21ED', name: 'Widevine' },
  PLAYREADY: { id: '9A04F07998404286AB92E65BE0885F95', name: 'PlayReady' },
  MARLIN: { id: '5E629AF538DA4063897797FFBD9902D4', name: 'Marlin' },
  COMMON: { id: '1077EFECC0B24D02ACE33C1E52E2FB4B', name: 'Common' }
}

const decodeWidevineHeader = (data: Buffer) => {
  const protoFile = path.join(__dirname, 'proto', 'WidevineCencHeader.proto')
  const root = protobuf.loadSync(protoFile)

  const WidevineCencHeader = root.lookupType('proto.WidevineCencHeader')
  const message = WidevineCencHeader.decode(data)
  const header = WidevineCencHeader.toObject(message, {
    enums: String,
    bytes: String,
    defaults: false,
    arrays: false
  })

  return header
}

const createPsshHeader = (version: number) => {
  const psshHeaderBuffer = Buffer.from([0x70, 0x73, 0x73, 0x68])

  const versionBuffer = Buffer.alloc(2)
  versionBuffer.writeInt16LE(version, 0)

  const flagBuffer = Buffer.alloc(2)
  flagBuffer.writeInt16BE(0, 0)

  return Buffer.concat([psshHeaderBuffer, versionBuffer, flagBuffer])
}

export const getPsshHeader = (request: HeaderConfig): string => {
  const pssh = []
  const keyIds = request.keyIds || []

  // Set default to 0 for Widevine backward compatibility
  let version = 0
  if (request.systemId !== system.WIDEVINE.id && keyIds.length > 0) {
    version = 1
  }

  // pssh header
  const psshHeader = createPsshHeader(version)
  pssh.push(psshHeader)

  // system id
  const systemIdBuffer = Buffer.from(request.systemId, 'hex')
  pssh.push(systemIdBuffer)

  // key ids
  if (version === 1) {
    const keyCountBuffer = Buffer.alloc(4)
    keyCountBuffer.writeInt32BE(keyIds.length, 0)
    pssh.push(keyCountBuffer)

    const kidsBufferArray = []
    for (let i = 0; i < keyIds.length; i++) {
      kidsBufferArray.push(Buffer.from(keyIds[i], 'hex'))
    }
    const kidsBuffer = Buffer.concat(kidsBufferArray)
    if (kidsBuffer.length > 0) {
      pssh.push(kidsBuffer)
    }
  }

  // data
  const dataBuffer = Buffer.from(request.data, 'base64')
  const dataSizeBuffer = Buffer.alloc(4)
  dataSizeBuffer.writeInt32BE(dataBuffer.length, 0)

  pssh.push(dataSizeBuffer)
  pssh.push(dataBuffer)

  // total size
  const psshSizeBuffer = Buffer.alloc(4)
  let totalLength = 4
  pssh.forEach((data) => {
    totalLength += data.length
  })
  psshSizeBuffer.writeInt32BE(totalLength, 0)
  pssh.unshift(psshSizeBuffer)

  return Buffer.concat(pssh).toString('base64')
}

export const decodePssh = (data: string) => {
  const result: DecodeResult = {}
  const decodedData = Buffer.from(data, 'base64')

  // pssh header
  const psshSize = Buffer.alloc(4)
  decodedData.copy(psshSize, 0, 0, 4)
  const psshHeader = Buffer.alloc(4)
  decodedData.copy(psshHeader, 0, 4, 8)

  // fullbox header
  const headerVersion = Buffer.alloc(2)
  decodedData.copy(headerVersion, 0, 8, 10)
  const psshVersion = headerVersion.readInt16LE(0)

  const headerFlag = Buffer.alloc(2)
  decodedData.copy(headerFlag, 0, 10, 12)

  // system id
  const systemId = Buffer.alloc(16)
  decodedData.copy(systemId, 0, 12, 28)

  let dataStartPosition = 28

  let keyCountInt = 0
  if (psshVersion === 1) {
    // key count
    const keyCount = Buffer.alloc(4)
    decodedData.copy(keyCount, 0, 28, 32)

    keyCountInt = keyCount.readInt32BE(0)

    if (keyCountInt > 0) {
      result.keyIds = []
      for (let i = 0; i < keyCountInt; i++) {
        // key id
        const keyId = Buffer.alloc(16)
        decodedData.copy(keyId, 0, 32 + (i * 16), 32 + ((i + 1) * 16))
        result.keyIds.push(keyId.toString('hex'))
      }
    }
    dataStartPosition = 32 + (16 * keyCountInt)
  }

  // data size
  const dataSize = Buffer.alloc(4)
  decodedData.copy(dataSize, 0, dataStartPosition, dataStartPosition + dataSize.length)
  const psshDataSize = dataSize.readInt32BE(0)

  // data
  const psshData = Buffer.alloc(psshDataSize)
  decodedData.copy(psshData, 0, dataStartPosition + dataSize.length, dataStartPosition + dataSize.length + psshData.length)

  let systemName = ''
  let widevineKeyCount = 0

  switch (systemId.toString('hex').toUpperCase()) {
    case system.WIDEVINE.id:
      systemName = system.WIDEVINE.name
      result.dataObject = decodeWVData(psshData)
      widevineKeyCount = result.dataObject.widevineKeyCount || 0
      break
    case system.PLAYREADY.id:
      systemName = system.PLAYREADY.name
      result.dataObject = decodePRData(psshData)
      break
    case system.MARLIN.id:
      systemName = system.MARLIN.name
      break
    default:
      systemName = 'common'
  }

  result.systemId = systemId
  result.systemName = systemName
  result.version = psshVersion
  result.keyCount = keyCountInt + widevineKeyCount

  result.printPssh = () => {
    // pssh version
    const psshArray = [`PSSH Box v${psshVersion}`]

    // system id
    psshArray.push(`  System ID: ${systemName} ${stringHexToGuid(systemId.toString('hex'))}`)

    // key ids
    if (result.keyIds && result.keyIds.length) {
      psshArray.push(`  Key IDs (${result.keyIds.length}):`)
      result.keyIds.forEach((key) => {
        const keyGuid = stringHexToGuid(key)
        psshArray.push(`    ${keyGuid}`)
      })
    }

    // pssh data size
    psshArray.push(`  PSSH Data (size: ${psshDataSize}):`)
    if (psshDataSize > 0) {
      psshArray.push(`    ${systemName} Data:`)

      // widevine data
      if (systemName === system.WIDEVINE.name && result.dataObject) {
        const dataObject: WidevineData = result.dataObject as WidevineData
        if (dataObject.keyId) {
          psshArray.push(`      Key IDs (${dataObject.keyId.length})`)
          dataObject.keyId.forEach((key) => {
            const keyGuid = stringHexToGuid(key)
            psshArray.push(`        ${keyGuid}`)
          })
        }
        if (dataObject.provider) {
          psshArray.push(`      Provider: ${dataObject.provider}`)
        }
        if (dataObject.contentId) {
          psshArray.push('      Content ID')
          psshArray.push(`        - UTF-8: ${Buffer.from(dataObject.contentId, 'hex').toString('utf8')}`)
          psshArray.push(`        - HEX  : ${dataObject.contentId}`)
        }
      }

      // playready data
      if (systemName === system.PLAYREADY.name && result.dataObject) {
        const dataObject: PlayReadyData = result.dataObject as PlayReadyData
        psshArray.push(`      Record size(${dataObject.recordSize})`)
        if (dataObject.recordType) {
          switch (dataObject.recordType) {
            case 1:
              psshArray.push(`        Record Type: Rights Management Header (${dataObject.recordType})`)
              break
            case 3:
              psshArray.push(`        Record Type: Embedded License Store (${dataObject.recordType})`)
              break
          }
        }
        if (dataObject.recordXml) {
          psshArray.push('        Record XML:')
          psshArray.push(`          ${dataObject.recordXml}`)
        }
      }
    }

    // line break
    psshArray.push('\n')
    return psshArray.join('\n')
  }

  return result
}

const decodeWVData = (psshData: Buffer): WidevineData => {
  // cenc header
  const header = decodeWidevineHeader(psshData)
  const wvData: WidevineData = {}

  if (header.keyId && header.keyId.length > 0) {
    wvData.widevineKeyCount = header.keyId.length
    const decodedKeys = header.keyId.map((key: string) => {
      return Buffer.from(key, 'base64').toString('hex')
    })
    wvData.keyId = decodedKeys
  }
  if (header.provider) {
    wvData.provider = header.provider
  }
  if (header.contentId) {
    wvData.contentId = Buffer.from(header.contentId, 'base64').toString('hex').toUpperCase()
  }
  return wvData
}

const decodePRData = (psshData: Buffer): PlayReadyData => {
  // pro header
  const proHeader = Buffer.alloc(10)
  psshData.copy(proHeader, 0, 0, 10)

  const proHeaderLength = proHeader.readInt32LE(0)
  // let proRecordCount = proHeader.readInt16LE(4)
  const proRecordType = proHeader.readInt16LE(6)
  const proDataLength = proHeader.readInt16LE(8)
  const proData = Buffer.alloc(proDataLength)
  psshData.copy(proData, 0, 10, proHeaderLength)

  return {
    recordSize: proDataLength,
    recordType: proRecordType,
    recordXml: proData.toString('utf16le')
  }
}

const stringHexToGuid = (value: string) => {
  const guidArray = []
  guidArray.push(value.slice(0, 8))
  guidArray.push(value.slice(8, 12))
  guidArray.push(value.slice(12, 16))
  guidArray.push(value.slice(16, 20))
  guidArray.push(value.slice(20, 32))
  return guidArray.join('-')
}

export const decodePsshData = (targetSystem: string, data: string) => {
  const dataBuffer = Buffer.from(data, 'base64')
  if (system.WIDEVINE.name === targetSystem) {
    return decodeWVData(dataBuffer)
  }
  if (system.PLAYREADY.name === targetSystem) {
    return decodePRData(dataBuffer)
  }
  return null
}
