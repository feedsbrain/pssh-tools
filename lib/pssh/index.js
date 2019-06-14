const widevine = require('./widevine')
const playready = require('./playready')

const { system } = require('./utils')

const tools = (systemName) => {
  switch (systemName) {
    case system.WIDEVINE.name:
      return widevine
    case system.PLAYREADY.name:
      return playready
    default:
      throw new Error('Unknown drm system')
  }
}

module.exports = {
  system,
  tools
}
