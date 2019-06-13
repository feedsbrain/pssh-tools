const test = require('ava')
const pssh = require('../index')
const utils = require('../lib/pssh/utils')

const KID = '0123456789abcdef0123456789abcdef'
const LA_URL = 'https://test.playready.microsoft.com/service/rightsmanager.asmx'

test('Should return Widevine PSSH version 0 with no KID', async t => {
  const wvTools = pssh.tools(pssh.system.WIDEVINE.name)
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', keyIds: [KID], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }
  await wvTools.generatePssh(payload).then((data) => {
    console.log(data)
    let result = utils.decodePSSH(data)
    t.is(result.version, 0)
    t.is(result.keyCount, 0)
  })
})

test.skip('Should return Widevine PSSH version 0 with KIDs', async t => {
  const wvTools = pssh.tools(pssh.system.WIDEVINE.name)
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', keyIds: [KID], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: false }
  await wvTools.generatePssh(payload).then((data) => {
    console.log(data)
    let result = utils.decodePSSH(data)
    t.is(result.version, 0)
    t.not(result.keyCount, 0)
  })
})

test('Should return PlayReady PSSH version 1 with KID', async t => {
  const prTools = pssh.tools(pssh.system.PLAYREADY.name)
  const payload = { keyIds: [KID], licenseUrl: LA_URL, dataOnly: false }
  await prTools.generatePssh(payload).then((data) => {
    let result = utils.decodePSSH(data)
    t.is(result.version, 1)
    t.is(result.keyCount, 1)
  })
})
