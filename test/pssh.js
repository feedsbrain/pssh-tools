const test = require('ava')
const pssh = require('../index')
const utils = require('../lib/pssh/utils')

const KID = '0123456789abcdef0123456789abcdef'
const LA_URL = 'https://test.playready.microsoft.com/service/rightsmanager.asmx'
const PSSH_TEST = 'AAAAQXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAACESEJjp6TNjifjKjuoDBeg+VrUaCmludGVydHJ1c3QiASo='

test('Should return Widevine PSSH version 0 without KID', t => {
  const wvTools = pssh.tools(pssh.system.WIDEVINE.name)
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }
  const data = wvTools.generatePssh(payload)

  console.log(data)
  let result = utils.decodePSSH(data)

  t.is(result.version, 0)
  t.is(result.keyCount, 0)
})

test('Should return Widevine PSSH version 0 with KIDs', t => {
  const wvTools = pssh.tools(pssh.system.WIDEVINE.name)
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', keyIds: [KID], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }

  const data = wvTools.generatePssh(payload)
  console.log(data)

  let result = utils.decodePSSH(data)
  t.is(result.version, 0)
  t.not(result.keyCount, 0)
})

test('Should return PlayReady PSSH version 1 with KID', t => {
  const prTools = pssh.tools(pssh.system.PLAYREADY.name)
  const payload = { keyIds: [KID], licenseUrl: LA_URL, dataOnly: false }

  const data = prTools.generatePssh(payload)
  let result = utils.decodePSSH(data)

  t.is(result.version, 1)
  t.is(result.keyCount, 1)
})

test('Should be able to decode PSSH generated from PSSH-BOX', t => {
  let result = utils.decodePSSH(PSSH_TEST)
  t.is(result.version, 0)
  t.is(result.keyCount, 1)
})
