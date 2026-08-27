import neostandard from 'neostandard'

export default [
  {
    ignores: ['dist/**', 'coverage/**', '.nyc_output/**', 'node_modules/**']
  },
  ...neostandard({
    ts: true,
    noStyle: false
  })
]
