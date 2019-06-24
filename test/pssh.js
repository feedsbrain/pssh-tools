const test = require('ava')
const pssh = require('../index')

const KID = '0123456789abcdef0123456789abcdef'
const LA_URL = 'https://test.playready.microsoft.com/service/rightsmanager.asmx'
const PSSH_TEST = 'AAAAQXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACESEJjp6TNjifjKjuoDBeg+VrUaCmludGVydHJ1c3QiASo='

test('Should return Widevine PSSH version 0 without KID', t => {
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }

  const data = pssh.widevine.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  t.is(result.version, 0)
  t.is(result.keyCount, 0)
})

test('Should return Widevine PSSH version 0 with KIDs', t => {
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', keyIds: [KID], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }

  const data = pssh.widevine.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  console.log(result.printPssh())

  t.is(result.version, 0)
  t.not(result.keyCount, 0)
})

test('Should return PlayReady PSSH version 1 with KID', t => {
  const payload = { keyIds: [KID], licenseUrl: LA_URL, dataOnly: false }

  const data = pssh.playready.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  console.log(result.printPssh())

  t.is(result.version, 1)
  t.is(result.keyCount, 1)
})

test('Should return PlayReady PSSH version 1 with Header Version 4.0.0.0 and KID', t => {
  const payload = { keyIds: [KID], licenseUrl: LA_URL, compatibilityMode: true, dataOnly: false }

  const data = pssh.playready.encodePssh(payload)
  const result = pssh.tools.decodePssh(data)

  console.log(result.printPssh())

  t.is(result.version, 1)
  t.is(result.keyCount, 1)
})

test('Should be able to decode PSSH generated from PSSH-BOX', t => {
  const result = pssh.tools.decodePssh(PSSH_TEST)
  console.log(result.printPssh())

  t.is(result.version, 0)
  t.is(result.keyCount, 1)
})
