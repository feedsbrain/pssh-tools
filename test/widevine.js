const test = require('ava')
const pssh = require('../index')

const KID = '0123456789abcdef0123456789abcdef'
const PSSH_DATA = 'CAESEAEjRWeJq83vASNFZ4mrze8aDXdpZGV2aW5lX3Rlc3QiD2NlbmMtY29udGVudC1pZA=='

test('ava runner', async t => {
  const wvTools = pssh.tools(pssh.system.WIDEVINE)
  const payload = { contentId: 'cenc-content-id', trackType: 'HD', keyIds: [KID], provider: 'widevine_test', protectionScheme: 'cenc', dataOnly: true }
  await wvTools.generatePssh(payload).then((data) => {
    t.is(data, PSSH_DATA)
  })
})
