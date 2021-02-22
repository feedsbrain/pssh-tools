import test from 'ava'
import * as pssh from '../src/index'
import { WidevineEncodeConfig, PlayReadyEncodeConfig, PlayReadyData } from '../src/lib/types'

const KID = '6f651ae1dbe44434bcb4690d1564c41c'
const KEY = '2a85da88fae41e2e36aeb2d5c94997b1'

const KEY_SEED = 'XVBovsmzhP9gRIZxWfFta3VVRPzVEWmJsazEJ46I'
const KS_KEY = '88da852ae4fa2e1e36aeb2d5c94997b1'

const PRO_KID = '4Rplb+TbNES8tGkNFWTEHA=='
const PRO_CONTENT_KEY = 'iNqFKuT6Lh42rrLVyUmXsQ=='
const PRO_KS_CONTENT_KEY = 'KoXaiPrkHi42rrLVyUmXsQ=='
const PRO_CHECKSUM_KEY = 'f8Acn4I4wU0='

const LA_URL = 'https://test.playready.microsoft.com/service/rightsmanager.asmx'
const PSSH_TEST = 'AAAAQXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACESEJjp6TNjifjKjuoDBeg+VrUaCmludGVydHJ1c3QiASo='
const PSSH_DATA_PR = 'pAIAAAEAAQCaAjwAVwBSAE0ASABFAEEARABFAFIAIAB4AG0AbABuAHMAPQAiAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAG0AaQBjAHIAbwBzAG8AZgB0AC4AYwBvAG0ALwBEAFIATQAvADIAMAAwADcALwAwADMALwBQAGwAYQB5AFIAZQBhAGQAeQBIAGUAYQBkAGUAcgAiACAAdgBlAHIAcwBpAG8AbgA9ACIANAAuADAALgAwAC4AMAAiAD4APABEAEEAVABBAD4APABQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsARQBZAEwARQBOAD4AMQA2ADwALwBLAEUAWQBMAEUATgA+ADwAQQBMAEcASQBEAD4AQQBFAFMAQwBUAFIAPAAvAEEATABHAEkARAA+ADwALwBQAFIATwBUAEUAQwBUAEkATgBGAE8APgA8AEsASQBEAD4AWgAwAFUAagBBAGEAdQBKADcAOAAwAEIASQAwAFYAbgBpAGEAdgBOADcAdwA9AD0APAAvAEsASQBEAD4APABDAEgARQBDAEsAUwBVAE0APgAwAHgAOQAxAFcARgB0AEcAWABCAEkAPQA8AC8AQwBIAEUAQwBLAFMAVQBNAD4APABMAEEAXwBVAFIATAA+AGgAdAB0AHAAOgAvAC8AdABlAHMAdAAuAHAAbABhAHkAcgBlAGEAZAB5AC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAHMAZQByAHYAaQBjAGUALwByAGkAZwBoAHQAcwBtAGEAbgBhAGcAZQByAC4AYQBzAG0AeAA8AC8ATABBAF8AVQBSAEwAPgA8AC8ARABBAFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA=='

test('Should return Widevine PSSH version 0 without KID', t => {
  const payload: WidevineEncodeConfig = { contentId: 'cenc-content-id', trackType: 'HD', provider: 'widevine_test', keyIds: [], protectionScheme: 'cenc', dataOnly: false }

  const data = pssh.widevine.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  t.is(result.version, 0)
  t.is(result.keyCount, 0)
})

test('Should return Widevine PSSH version 0 with KIDs', t => {
  const payload: WidevineEncodeConfig = { contentId: 'cenc-content-id', trackType: 'HD', keyIds: [KID], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }

  const data = pssh.widevine.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  if (result.printPssh) {
    console.log(result.printPssh())
  }

  t.is(result.version, 0)
  t.not(result.keyCount, 0)
})

test('Should return Widevine PSSH version 0 with Multiple KIDs', t => {
  const payload: WidevineEncodeConfig = { contentId: 'cenc-content-id', keyIds: [KID, KS_KEY], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }

  const data = pssh.widevine.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  if (result.printPssh) {
    console.log(result.printPssh())
  }

  t.is(result.version, 0)
  t.not(result.keyCount, 0)
})

test('Should return PlayReady PSSH version 1 with KID', t => {
  const payload: PlayReadyEncodeConfig = { keyPairs: [{ kid: KID, key: KEY }], licenseUrl: LA_URL, keySeed: '', compatibilityMode: false, dataOnly: false }

  const data = pssh.playready.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  if (result.printPssh) {
    console.log(result.printPssh())
  }

  t.is(result.version, 1)
  t.is(result.keyCount, 1)
})

test('Should return PlayReady PSSH version 1 with Header Version 4.0.0.0 and KID', t => {
  const payload: PlayReadyEncodeConfig = { keyPairs: [{ kid: KID, key: KEY }], licenseUrl: LA_URL, keySeed: '', compatibilityMode: true, dataOnly: false }

  const data = pssh.playready.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  if (result.printPssh) {
    console.log(result.printPssh())
  }

  t.is(result.version, 1)
  t.is(result.keyCount, 1)
})

test('Should return PRO w/ Checksum', t => {
  const payload: PlayReadyEncodeConfig = { keyPairs: [{ kid: KID, key: KEY }], licenseUrl: LA_URL, keySeed: '', compatibilityMode: true, dataOnly: true }
  const data = pssh.playready.encodePssh(payload)
  const result: PlayReadyData = pssh.playready.decodeData(data) as PlayReadyData

  if (result && result.recordXml && result.recordSize) {
    t.is(result.recordXml.includes('CHECKSUM'), true)
  } else {
    t.fail()
  }
})

test('Should return PRO w/o Checksum', t => {
  const payload: PlayReadyEncodeConfig = { keyPairs: [{ kid: KID, key: KEY }], licenseUrl: LA_URL, keySeed: '', compatibilityMode: true, dataOnly: true, checksum: false }
  const data = pssh.playready.encodePssh(payload)
  const result: PlayReadyData = pssh.playready.decodeData(data) as PlayReadyData

  if (result && result.recordXml && result.recordSize) {
    t.is(result.recordXml.includes('CHECKSUM'), false)
  } else {
    t.fail()
  }
})

test('Should be able to decode PSSH generated from PSSH-BOX', t => {
  const result = pssh.tools.decodePssh(PSSH_TEST)
  if (result.printPssh) {
    console.log(result.printPssh())
  }

  t.is(result.version, 0)
  t.is(result.keyCount, 1)
})

test('Should be able to decode PlayReady PSSH data', t => {
  const result: PlayReadyData = pssh.playready.decodeData(PSSH_DATA_PR) as PlayReadyData
  if (result && result.recordXml && result.recordSize) {
    console.log('PR Data:', result.recordXml)
    t.not(result.recordSize, 0)
  }
})

test('Should be able to decode PlayReady static content key', t => {
  const result = pssh.playready.decodeKey(PRO_CONTENT_KEY)
  console.log(`\nKey ID: ${result}\n`)

  t.is(result, KEY)
})

test('Should be able to decode PlayReady generated content key', t => {
  const result = pssh.playready.decodeKey(PRO_KS_CONTENT_KEY)
  console.log(`\nKey ID: ${result}\n`)

  t.is(result, KS_KEY)
})

test('Should be able to encode PlayReady content key with correct checksum', t => {
  const result = pssh.playready.encodeKey({ kid: KID, key: KEY })
  console.log(`\nKey: ${JSON.stringify(result, null, 2)}\n`)

  t.not(result, undefined)
  t.is(result.kid, PRO_KID)
  t.is(result.key, PRO_CONTENT_KEY)
  t.is(result.checksum, PRO_CHECKSUM_KEY)
})

test('Should be able to encode PlayReady content key using test key seed with correct checksum', t => {
  const result = pssh.playready.encodeKey({ kid: KID, key: '' }, KEY_SEED)
  const control = pssh.playready.encodeKey({ kid: KID, key: KS_KEY })

  console.log(`\nKey: ${JSON.stringify(result, null, 2)}\n`)

  t.not(result, undefined)
  t.is(result.kid, PRO_KID)
  t.is(result.key, control.key)
  t.is(result.checksum, control.checksum)
})

test('Should be able to encode PlayReady content key using kid and key with correct checksum', t => {
  const result = pssh.playready.encodeKey({ kid: KID, key: KEY })
  console.log(`\nKey: ${JSON.stringify(result, null, 2)}\n`)

  t.not(result, undefined)
  t.is(result.kid, PRO_KID)
  t.is(result.key, PRO_CONTENT_KEY)
  t.is(result.checksum, PRO_CHECKSUM_KEY)
})

test('Should return PlayReady PRO without LA_URL', t => {
  const payload: PlayReadyEncodeConfig = { keyPairs: [{ kid: KID, key: KEY }], keySeed: '', compatibilityMode: true, dataOnly: false }

  const data = pssh.playready.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  if (result.printPssh) {
    console.log(result.printPssh())
  }

  if (result.dataObject) {
    const pro: PlayReadyData = result.dataObject as PlayReadyData
    t.is(pro.recordXml.includes(LA_URL), false)
  }
})

test('Should return PlayReady PRO with LA_URL', t => {
  const payload: PlayReadyEncodeConfig = { keyPairs: [{ kid: KID, key: KEY }], licenseUrl: LA_URL, keySeed: '', compatibilityMode: true, dataOnly: false }

  const data = pssh.playready.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  if (result.printPssh) {
    console.log(result.printPssh())
  }

  if (result.dataObject) {
    const pro: PlayReadyData = result.dataObject as PlayReadyData
    t.is(pro.recordXml.includes(LA_URL), true)
  }
})
