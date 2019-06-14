const path = require('path')
const protobuf = require('protobufjs')

const utils = require('./utils')

const getPsshData = ({ contentId = null, trackType = '', keyIds = [], provider = '', protectionScheme = 'cenc' }) => {
  const protoFile = path.join(__dirname, 'proto', 'WidevineCencHeader.proto')
  const root = protobuf.loadSync(protoFile)

  const WidevineCencHeader = root.lookupType('proto.WidevineCencHeader')
  const payload = {
    algorithm: 1 // 0: Unencrypted - 1: AESCTR
  }
  if (keyIds !== [] && keyIds.length > 0) {
    const keyIdsBuffer = keyIds.map((key) => {
      return Buffer.from(key, 'hex')
    })
    payload.keyId = keyIdsBuffer
  }
  if (contentId !== null) {
    payload.contentId = Buffer.from(contentId)
  }
  if (trackType !== '') {
    payload.trackType = trackType
  }
  if (provider !== '') {
    payload.provider = provider
  }
  if (protectionScheme !== '') {
    payload.protectionScheme = Buffer.from(protectionScheme).readInt32BE()
  }

  const errMsg = WidevineCencHeader.verify(payload)
  if (errMsg) {
    throw new Error(errMsg)
  }

  const message = WidevineCencHeader.create(payload)
  const buffer = WidevineCencHeader.encode(message).finish()

  return buffer.toString('base64')
}

const getPsshBox = ({ contentId, keyIds = [], provider = '', protectionScheme = 'cenc' }) => {
  // data
  const data = getPsshData({
    contentId: contentId,
    keyIds: keyIds,
    provider: provider,
    protectionScheme: protectionScheme
  })
  const psshHeader = utils.getPsshHeader({
    systemId: utils.system.WIDEVINE.id,
    keyIds: keyIds,
    data: data
  })
  return psshHeader
}

const encodePssh = ({ contentId, keyIds = [], provider = '', protectionScheme = 'cenc', dataOnly = false }) => {
  if (dataOnly) {
    return getPsshData({
      contentId: contentId,
      keyIds: keyIds,
      provider: provider,
      protectionScheme: protectionScheme
    })
  }
  return getPsshBox({
    contentId: contentId,
    keyIds: keyIds,
    provider: provider,
    protectionScheme: protectionScheme
  })
}

const decodePssh = (data) => {
  return utils.decodePSSH(data)
}

module.exports = {
  encodePssh,
  decodePssh
}
