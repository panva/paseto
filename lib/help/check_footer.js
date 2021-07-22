const isObject = require('./is_object')

module.exports = function checkFooter(footer) {
  if (typeof footer === 'undefined') {
    return Buffer.from('')
  }

  if (Buffer.isBuffer(footer)) {
    return footer
  }

  if (isObject(footer)) {
    return Buffer.from(JSON.stringify(footer), 'utf8')
  }

  if (typeof footer !== 'string') {
    throw new TypeError('options.footer must be a string, Buffer, or a plain object')
  }

  return Buffer.from(footer, 'utf8')
}
