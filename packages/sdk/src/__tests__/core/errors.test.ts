import { describe, expect, it } from 'vitest';
import { ErrorCodes, IgnotiError } from '../../core/errors';

describe('IgnotiError', () => {
  it('sets name, message, and code', () => {
    const err = new IgnotiError('bad thing', ErrorCodes.INVALID_INPUT);
    expect(err.name).toBe('IgnotiError');
    expect(err.message).toBe('bad thing');
    expect(err.code).toBe(ErrorCodes.INVALID_INPUT);
  });

  it('sets httpStatus when provided', () => {
    const err = new IgnotiError('not found', ErrorCodes.API_ERROR, undefined, 404);
    expect(err.httpStatus).toBe(404);
  });

  it('httpStatus is undefined when not provided', () => {
    const err = new IgnotiError('oops', ErrorCodes.CRYPTOGRAPHY_ERROR);
    expect(err.httpStatus).toBeUndefined();
  });

  it('attaches cause', () => {
    const cause = new Error('root cause');
    const err = new IgnotiError('wrapper', ErrorCodes.API_ERROR, cause);
    expect(err.cause).toBe(cause);
  });

  it('works without cause', () => {
    const err = new IgnotiError('no cause', ErrorCodes.NO_KEYS);
    expect(err.cause).toBeUndefined();
  });

  it('all ErrorCodes are defined strings', () => {
    expect(Object.keys(ErrorCodes).length).toBeGreaterThan(0);
    for (const code of Object.values(ErrorCodes)) {
      expect(typeof code).toBe('string');
    }
  });
});
