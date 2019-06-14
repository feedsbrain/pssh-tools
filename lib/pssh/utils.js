const path = require('path')
const protobuf = require('protobufjs')

const system = {
  WIDEVINE: { id: 'EDEF8BA979D64ACEA3C827DCD51D21ED', name: 'Widevine' },
  PLAYREADY: { id: '9A04F07998404286AB92E65BE0885F95', name: 'PlayReady' },
  MARLIN: { id: '5E629AF538DA4063897797FFBD9902D4', name: 'Marlin' },
  COMMON: { id: '1077EFECC0B24D02ACE33C1E52E2FB4B', name: 'Common' }
}

const decodeWidevineHeader = (data) => {
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

const createPsshHeader = (version) => {
  let psshHeaderBuffer = Buffer.from([0x70, 0x73, 0x73, 0x68])

  let versionBuffer = Buffer.alloc(2)
  versionBuffer.writeInt16LE(version)

  let flagBuffer = Buffer.alloc(2)
  flagBuffer.writeInt16BE(0)

  return Buffer.concat([psshHeaderBuffer, versionBuffer, flagBuffer])
}

const getPsshHeader = ({ systemId = undefined, keyIds = [], data }) => {
  const pssh = []

  // Set default to 0 for Widevine backward compatibility
  let version = 0
  if (systemId !== system.WIDEVINE.id && keyIds.length > 0) {
    version = 1
  }

  // pssh header
  const psshHeader = createPsshHeader(version)
  pssh.push(psshHeader)

  // system id
  const systemIdBuffer = Buffer.from(systemId, 'hex')
  pssh.push(systemIdBuffer)

  // key ids
  if (version === 1) {
    let keyCountBuffer = Buffer.alloc(4)
    keyCountBuffer.writeInt32BE(keyIds.length)
    pssh.push(keyCountBuffer)

    let kidsBufferArray = []
    for (let i = 0; i < keyIds.length; i++) {
      kidsBufferArray.push(Buffer.from(keyIds[i], 'hex'))
    }
    let kidsBuffer = Buffer.concat(kidsBufferArray)
    if (kidsBuffer.length > 0) {
      pssh.push(kidsBuffer)
    }
  }

  // data
  let dataBuffer = Buffer.from(data, 'base64')
  let dataSizeBuffer = Buffer.alloc(4)
  dataSizeBuffer.writeInt32BE(dataBuffer.length)

  pssh.push(dataSizeBuffer)
  pssh.push(dataBuffer)

  // total size
  let psshSizeBuffer = Buffer.alloc(4)
  let totalLength = 4
  pssh.forEach((data) => {
    totalLength += data.length
  })
  psshSizeBuffer.writeInt32BE(totalLength)
  pssh.unshift(psshSizeBuffer)

  return Buffer.concat(pssh).toString('base64')
}

const decodePssh = (data) => {
  const result = {}
  const decodedData = Buffer.from(data, 'base64')

  // pssh header
  let psshSize = Buffer.alloc(4)
  decodedData.copy(psshSize, 0, 0, 4)
  let psshHeader = Buffer.alloc(4)
  decodedData.copy(psshHeader, 0, 4, 8)

  // fullbox header
  let headerVersion = Buffer.alloc(2)
  decodedData.copy(headerVersion, 0, 8, 10)
  let psshVersion = headerVersion.readInt16LE(0)

  let headerFlag = Buffer.alloc(2)
  decodedData.copy(headerFlag, 0, 10, 12)

  // system id
  let systemId = Buffer.alloc(16)
  decodedData.copy(systemId, 0, 12, 28)

  let dataStartPosition = 28

  let keyCountInt = 0
  if (psshVersion === 1) {
    // key count
    let keyCount = Buffer.alloc(4)
    decodedData.copy(keyCount, 0, 28, 32)

    keyCountInt = keyCount.readInt32BE(0)

    if (keyCountInt > 0) {
      result.keyIds = []
      for (let i = 0; i < keyCountInt; i++) {
        // key id
        let keyId = Buffer.alloc(16)
        decodedData.copy(keyId, 0, 32 + (i * 16), 32 + ((i + 1) * 16))
        result.keyIds.push(keyId.toString('hex'))
      }
    }
    dataStartPosition = 32 + (16 * keyCountInt)
  }

  // data size
  let dataSize = Buffer.alloc(4)
  decodedData.copy(dataSize, 0, dataStartPosition, dataStartPosition + dataSize.length)
  let psshDataSize = parseInt(dataSize.readInt32BE(0))

  // data
  let psshData = Buffer.alloc(psshDataSize)
  decodedData.copy(psshData, 0, dataStartPosition + dataSize.length, dataStartPosition + dataSize.length + psshData.length)

  let systemName = ''
  let widevineKeyCount = 0

  switch (systemId.toString('hex').toUpperCase()) {
    case system.WIDEVINE.id:
      systemName = system.WIDEVINE.name
      // cenc header
      let header = decodeWidevineHeader(psshData)
      let wvData = {}

      if (header.keyId && header.keyId.length > 0) {
        widevineKeyCount = header.keyId.length
        let decodedKeys = header.keyId.map((key) => {
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
      result.dataObject = wvData
      break
    case system.PLAYREADY.id:
      systemName = system.PLAYREADY.name
      // pro header
      let proHeader = Buffer.alloc(10)
      psshData.copy(proHeader, 0, 0, 10)

      let proHeaderLength = proHeader.readInt32LE(0)
      // let proRecordCount = proHeader.readInt16LE(4)
      let proRecordType = proHeader.readInt16LE(6)
      let proDataLength = proHeader.readInt16LE(8)
      let proData = Buffer.alloc(proDataLength)
      psshData.copy(proData, 0, 10, proHeaderLength)

      result.dataObject = {
        recordSize: proDataLength,
        recordType: proRecordType,
        recordXml: proData.toString('utf8')
      }
      break
    case system.MARLIN.id:
      systemName = system.MARLIN.name
      break
    default:
      systemName = 'common'
  }

  result.systemId = `${systemName}: ${systemId.toString('hex').toUpperCase()}`
  result.version = psshVersion
  result.keyCount = keyCountInt + widevineKeyCount

  result.printPssh = () => {
    // pssh version
    let psshArray = [`PSSH Box v${psshVersion}`]

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
        let dataObject = result.dataObject
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
          psshArray.push(`      Content ID: ${dataObject.contentId}`)
        }
      }

      // playready data
      if (systemName === system.PLAYREADY.name && result.dataObject) {
        let dataObject = result.dataObject
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

const stringHexToGuid = (value) => {
  var guidArray = []
  guidArray.push(value.slice(0, 8))
  guidArray.push(value.slice(8, 12))
  guidArray.push(value.slice(12, 16))
  guidArray.push(value.slice(16, 20))
  guidArray.push(value.slice(20, 32))
  return guidArray.join('-')
}

module.exports = {
  system,
  getPsshHeader,
  decodePSSH: decodePssh
}
