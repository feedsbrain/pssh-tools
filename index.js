const wv = require('./lib/widevine')

const getWidevinePsshData = (payload) => {
  return wv.generateWidevineCencHeader(payload)
}

module.exports = {
  getWidevinePsshData
}
