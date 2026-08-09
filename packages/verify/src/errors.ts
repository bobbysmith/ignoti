/**
 * Thrown when introspection itself fails (network error, timeout, or a
 * non-200 response). Distinct from `{ valid: false }`, which is a successful
 * introspection of an invalid session.
 */
export class IgnotiVerifyError extends Error {
  constructor(
    message: string,
    // HTTP status of the introspection response, if one was received.
    public readonly httpStatus?: number,
    cause?: unknown
  ) {
    super(message, cause ? { cause } : undefined);
    this.name = 'IgnotiVerifyError';
  }
}
