const CODES = {
  PasetoNotSupported: 'ERR_PASETO_NOT_SUPPORTED',
  PasetoDecryptionFailed: 'ERR_PASETO_DECRYPTION_FAILED',
  PasetoInvalid: 'ERR_PASETO_INVALID',
  PasetoVerificationFailed: 'ERR_PASETO_VERIFICATION_FAILED',
  PasetoClaimInvalid: 'ERR_PASETO_CLAIM_INVALID',
}

class PasetoError extends Error {
  constructor(message) {
    super(message)
    this.name = this.constructor.name
    this.code = CODES[this.constructor.name]
    Error.captureStackTrace(this, this.constructor)
  }
}

module.exports.PasetoError = PasetoError

module.exports.PasetoNotSupported = class PasetoNotSupported extends PasetoError {}
module.exports.PasetoDecryptionFailed = class PasetoDecryptionFailed extends PasetoError {}
module.exports.PasetoInvalid = class PasetoInvalid extends PasetoError {}
module.exports.PasetoVerificationFailed = class PasetoVerificationFailed extends PasetoError {}
module.exports.PasetoClaimInvalid = class PasetoClaimInvalid extends PasetoError {}
