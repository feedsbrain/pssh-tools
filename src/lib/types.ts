type Omit<K, KEY extends keyof K> = Pick<K, Exclude<keyof K, KEY>>

export interface WidevineEncodeConfig {
  contentId: string
  dataOnly: boolean
  keyIds?: string[]
  provider?: string
  protectionScheme?: string
  trackType?: string
  algorithm?: boolean
}

export type WidevineDataEncodeConfig = Omit<WidevineEncodeConfig, 'dataOnly'>

export interface KeyPair {
  kid: string
  key: string
}

export interface PlayReadyEncodeConfig {
  keyPairs?: KeyPair[]
  licenseUrl?: string
  keySeed?: string
  compatibilityMode: boolean
  dataOnly: boolean
  checksum?: boolean
}

export type PlayReadyDataEncodeConfig = Omit<PlayReadyEncodeConfig, 'dataOnly'>

export interface HeaderConfig {
  systemId: string
  keyIds?: string[]
  data: string
}

export interface PlayReadyData {
  recordSize: number
  recordType: number
  recordXml: string
}

export interface WidevineData {
  widevineKeyCount?: number
  keyId?: string[]
  provider?: string
  contentId?: string
}

export type PsshData = PlayReadyData | WidevineData

export interface DecodeResult {
  keyIds?: string[]
  dataObject?: PsshData
  systemId?: Buffer
  systemName?: string
  version?: number
  keyCount?: number
  printPssh?: Function
}
