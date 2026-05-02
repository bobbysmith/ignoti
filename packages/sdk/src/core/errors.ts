import { type ErrorCode, ErrorCodes } from '@/types';

export { type ErrorCode, ErrorCodes };

export class GhostIDError extends Error {
  constructor(
    message: string,
    public readonly code: ErrorCode,
    cause?: unknown,
    /** HTTP status code, populated only for API_ERROR responses. */
    public readonly httpStatus?: number
  ) {
    super(message, cause ? { cause } : undefined);
    this.name = 'GhostIDError';
    if (cause !== undefined && !('cause' in this)) {
      Object.defineProperty(this, 'cause', { value: cause, enumerable: false });
    }
  }
}
