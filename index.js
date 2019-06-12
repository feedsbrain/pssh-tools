const widevine = require('./lib/pssh/widevine')
const playready = require('./lib/pssh/playready')

const system = {
  WIDEVINE: 'widevine',
  PLAYREADY: 'playready'
}

const tools = (systemId) => {
  switch (systemId.toLowerCase()) {
    case system.WIDEVINE:
      return widevine
    case system.PLAYREADY:
      return playready
    default:
      throw new Error('Unknown drm system')
  }
}

module.exports = {
  system,
  tools
}
