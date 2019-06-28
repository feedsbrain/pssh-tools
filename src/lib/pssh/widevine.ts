import * as path from 'path'
import * as protobuf from 'protobufjs'
import * as T from '../types';

import * as tools from './tools'

interface WidevineProtoPayload {
  algorithm: number,
  keyId?: Buffer[],
  contentId?: Buffer,
  trackType?: string,
  provider?: string,
  protectionScheme?: number
}

const getPsshData = (request: T.WidevineDataEncodeConfig) => {
  const protoFile = path.join(__dirname, 'proto', 'WidevineCencHeader.proto')
  const root = protobuf.loadSync(protoFile)

  const WidevineCencHeader = root.lookupType('proto.WidevineCencHeader')
  const payload: WidevineProtoPayload = {
    algorithm: 1 // 0: Unencrypted - 1: AESCTR
  }
  if (request.keyIds !== [] && request.keyIds.length > 0) {
    const keyIdsBuffer = request.keyIds.map((key) => {
      return Buffer.from(key, 'hex')
    })
    payload.keyId = keyIdsBuffer
  }
  if (request.contentId) {
    payload.contentId = Buffer.from(request.contentId)
  }
  if (request.trackType !== '') {
    payload.trackType = request.trackType
  }
  if (request.provider !== '') {
    payload.provider = request.provider
  }
  if (request.protectionScheme !== '') {
    payload.protectionScheme = Buffer.from(request.protectionScheme).readInt32BE(0)
  }

  const errMsg = WidevineCencHeader.verify(payload)
  if (errMsg) {
    throw new Error(errMsg)
  }

  const message = WidevineCencHeader.create(payload)
  const buffer = WidevineCencHeader.encode(message).finish()

  return Buffer.from(buffer).toString('base64')
}

const getPsshBox = (request: T.WidevineDataEncodeConfig) => {
  // data
  const data = getPsshData(request)
  const requestData: T.HeaderConfig = {
    systemId: tools.system.WIDEVINE.id,
    keyIds: request.keyIds,
    data: data
  }
  const psshHeader = tools.getPsshHeader(requestData)
  return psshHeader
}

export const encodePssh = (request: T.WidevineEncodeConfig) => {
  if (request.dataOnly) {
    return getPsshData(request)
  }
  return getPsshBox(request)
}

export const decodeData = (data: string) => {
  return tools.decodePsshData(tools.system.WIDEVINE.name, data)
}
