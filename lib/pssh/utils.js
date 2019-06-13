const protobuf = require('protobufjs')

const system = {
  WIDEVINE: { id: 'EDEF8BA979D64ACEA3C827DCD51D21ED', name: 'widevine' },
  PLAYREADY: { id: '9A04F07998404286AB92E65BE0885F95', name: 'playready' },
  MARLIN: { id: '5E629AF538DA4063897797FFBD9902D4', name: 'marlin' },
  COMMON: { id: '1077EFECC0B24D02ACE33C1E52E2FB4B', name: 'common' }
}

const decodeWidevineHeader = (data) => {
  const root = protobuf.loadSync('./lib/pssh/proto/WidevineCencHeader.proto')

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

const decodePSSH = (data) => {
  console.log('\n')
  console.log('---------------')
  console.log(' Decoding PSSH ')
  console.log('---------------')
  const decodedData = Buffer.from(data, 'base64')

  // pssh header
  let psshSize = Buffer.alloc(4)
  decodedData.copy(psshSize, 0, 0, 4)
  console.log('PSSH Size:', psshSize.readInt32BE(0))
  let psshHeader = Buffer.alloc(4)
  decodedData.copy(psshHeader, 0, 4, 8)
  console.log('PSSH Header:', psshHeader.toString())

  // fullbox header
  let headerVersion = Buffer.alloc(2)
  decodedData.copy(headerVersion, 0, 8, 10)
  let psshVersion = headerVersion.readInt16LE(0)
  console.log('Header Version:', psshVersion)

  let headerFlag = Buffer.alloc(2)
  decodedData.copy(headerFlag, 0, 10, 12)
  console.log('Flag:', headerFlag.readInt16BE(0))

  // system id
  let systemId = Buffer.alloc(16)
  decodedData.copy(systemId, 0, 12, 28)
  console.log('System ID:', systemId.toString('hex'))

  let dataStartPosition = 28

  let keyCountInt = 0
  if (psshVersion === 1) {
    // key count
    let keyCount = Buffer.alloc(4)
    decodedData.copy(keyCount, 0, 28, 32)

    keyCountInt = keyCount.readInt32BE(0)
    console.log('Key Count:', keyCountInt)

    if (keyCountInt > 0) {
      console.log('Key IDs:')
      for (let i = 0; i < keyCountInt; i++) {
        // key id
        let keyId = Buffer.alloc(16)
        decodedData.copy(keyId, 0, 32 + (i * 16), 32 + ((i + 1) * 16))
        console.log(`  - ${keyId.toString('hex')}`)
      }
    }
    dataStartPosition = 32 + (16 * keyCountInt)
  }

  // data size
  let dataSize = Buffer.alloc(4)
  decodedData.copy(dataSize, 0, dataStartPosition, dataStartPosition + dataSize.length)
  let psshDataSize = parseInt(dataSize.readInt32BE(0))
  console.log('Data Size:', psshDataSize)

  // data
  let psshData = Buffer.alloc(psshDataSize)
  decodedData.copy(psshData, 0, dataStartPosition + dataSize.length, dataStartPosition + dataSize.length + psshData.length)
  console.log('\n')

  let widevineKeyCount = 0
  if (systemId.toString('hex').toUpperCase() === system.WIDEVINE.id) {
    // cenc header
    let header = decodeWidevineHeader(psshData)
    let decodedHeader = {}

    if (header.keyId && header.keyId.length > 0) {
      widevineKeyCount = header.keyId.length
      let decodedKeys = header.keyId.map((key) => {
        return Buffer.from(key, 'base64').toString('hex')
      })
      decodedHeader.keyId = decodedKeys
    }
    if (header.provider) {
      decodedHeader.provider = header.provider
    }
    if (header.contentId) {
      decodedHeader.contentId = Buffer.from(header.contentId, 'base64').toString('hex').toUpperCase()
    }

    console.log('Widevine Data:', decodedHeader)
  }

  if (systemId.toString('hex').toUpperCase() === system.PLAYREADY.id) {
    // pro header
    let proHeader = Buffer.alloc(10)
    psshData.copy(proHeader, 0, 0, 10)
    console.log('PRO Header:', proHeader)
    console.log('Length: ', proHeader.readInt32LE(0))
    console.log('Record Count: ', proHeader.readInt16LE(4))
    console.log('Record Type: ', proHeader.readInt16LE(6))
    console.log('Header Length: ', proHeader.readInt16LE(8))
  }

  let systemName = ''
  switch (systemId.toString('hex').toUpperCase()) {
    case system.WIDEVINE.id:
      systemName = system.WIDEVINE.name
      break
    case system.PLAYREADY.id:
      systemName = system.WIDEVINE.name
      break
    case system.MARLIN.id:
      systemName = system.WIDEVINE.name
      break
    default:
      systemName = 'common'
  }

  return {
    systemId: `${systemName.toUpperCase()}: ${systemId.toString('hex').toUpperCase()}`,
    version: psshVersion,
    keyCount: keyCountInt + widevineKeyCount
  }
}

module.exports = {
  system,
  getPsshHeader,
  decodePSSH
}
