/**
 * A generic Error subclass that all other specific
 * PASETO Error subclasses inherit from.
 */
export class PASETOError extends Error {
  /**
   * A unique error code for the particular error subclass.
   */
  static get code(): string {
    return 'ERR_PASETO_GENERIC'
  }

  /**
   * A unique error code for the particular error subclass.
   */
  code: string = 'ERR_PASETO_GENERIC'

  constructor(message?: string) {
    super(message)
    this.name = this.constructor.name
    Error.captureStackTrace?.(this, this.constructor)
  }
}

/**
 * An error subclass thrown when a PASETO Claim Set member validation fails.
 */
export class PASETOClaimValidationFailed extends PASETOError {
  static get code(): 'ERR_PASETO_CLAIM_VALIDATION_FAILED' {
    return 'ERR_PASETO_CLAIM_VALIDATION_FAILED'
  }

  code = 'ERR_PASETO_CLAIM_VALIDATION_FAILED'

  /**
   * The Claim for which the validation failed.
   */
  claim: string

  /**
   * Reason code for the validation failure.
   */
  reason: string

  constructor(message: string, claim = 'unspecified', reason = 'unspecified') {
    super(message)
    this.claim = claim
    this.reason = reason
  }
}

/**
 * An error subclass thrown when a PASETO is expired.
 */
export class PASETOExpired extends PASETOError implements PASETOClaimValidationFailed {
  static get code(): 'ERR_PASETO_EXPIRED' {
    return 'ERR_PASETO_EXPIRED'
  }

  code = 'ERR_PASETO_EXPIRED'

  /**
   * The Claim for which the validation failed.
   */
  claim: string

  /**
   * Reason code for the validation failure.
   */
  reason: string

  constructor(message: string, claim = 'unspecified', reason = 'unspecified') {
    super(message)
    this.claim = claim
    this.reason = reason
  }
}

/**
 * An error subclass thrown when a JWE ciphertext decryption fails.
 */
export class PASETODecryptionFailed extends PASETOError {
  static get code(): 'ERR_PASETO_DECRYPTION_FAILED' {
    return 'ERR_PASETO_DECRYPTION_FAILED'
  }

  code = 'ERR_PASETO_DECRYPTION_FAILED'

  message = 'decryption operation failed'
}

/**
 * An error subclass thrown when a PASETO is invalid.
 */
export class PASETOInvalid extends PASETOError {
  static get code(): 'ERR_PASETO_INVALID' {
    return 'ERR_PASETO_INVALID'
  }

  code = 'ERR_PASETO_INVALID'
}

/**
 * An error subclass thrown when a PASERK is invalid.
 */
export class PASERKInvalid extends PASETOError {
  static get code(): 'ERR_PASERK_INVALID' {
    return 'ERR_PASERK_INVALID'
  }

  code = 'ERR_PASERK_INVALID'
}

/**
 * An error subclass thrown when signature verification fails.
 */
export class PASETOSignatureVerificationFailed extends PASETOError {
  static get code(): 'ERR_PASETO_SIGNATURE_VERIFICATION_FAILED' {
    return 'ERR_PASETO_SIGNATURE_VERIFICATION_FAILED'
  }

  code = 'ERR_PASETO_SIGNATURE_VERIFICATION_FAILED'

  message = 'signature verification failed'
}
