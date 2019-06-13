const protobuf = require('protobufjs')
const utils = require('./utils')

const getPsshData = ({ contentId = null, trackType = '', keyIds = [], provider = '', protectionScheme = 'cenc' }) => {
  return new Promise((resolve, reject) => {
    protobuf.load('./lib/pssh/proto/WidevineCencHeader.proto', (err, root) => {
      if (err) {
        return reject(err)
      }

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
        return reject(new Error(errMsg))
      }

      const message = WidevineCencHeader.create(payload)
      const buffer = WidevineCencHeader.encode(message).finish()

      return resolve(buffer.toString('base64'))
    })
  })
}

const getPsshBox = ({ contentId, keyIds = [], provider = '', protectionScheme = 'cenc' }) => {
  return new Promise((resolve, reject) => {
    // data
    getPsshData({
      contentId: contentId,
      keyIds: keyIds,
      provider: provider,
      protectionScheme: protectionScheme
    }).then((data) => {
      let psshHeader = utils.getPsshHeader({
        systemId: utils.system.WIDEVINE.id,
        keyIds: keyIds,
        data: data
      })
      return resolve(psshHeader)
    }).catch((err) => {
      return reject(err)
    })
  })
}

const generatePssh = ({ contentId, keyIds = [], provider = '', protectionScheme = 'cenc', dataOnly = false }) => {
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

module.exports = {
  generatePssh
}
