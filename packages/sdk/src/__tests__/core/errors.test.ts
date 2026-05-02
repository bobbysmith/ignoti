import { describe, expect, it } from 'vitest';
import { ErrorCodes, GhostIDError } from '../../core/errors';

describe('GhostIDError', () => {
  it('sets name, message, and code', () => {
    const err = new GhostIDError('bad thing', ErrorCodes.INVALID_INPUT);
    expect(err.name).toBe('GhostIDError');
    expect(err.message).toBe('bad thing');
    expect(err.code).toBe(ErrorCodes.INVALID_INPUT);
  });

  it('sets httpStatus when provided', () => {
    const err = new GhostIDError('not found', ErrorCodes.API_ERROR, undefined, 404);
    expect(err.httpStatus).toBe(404);
  });

  it('httpStatus is undefined when not provided', () => {
    const err = new GhostIDError('oops', ErrorCodes.CRYPTOGRAPHY_ERROR);
    expect(err.httpStatus).toBeUndefined();
  });

  it('attaches cause', () => {
    const cause = new Error('root cause');
    const err = new GhostIDError('wrapper', ErrorCodes.API_ERROR, cause);
    expect(err.cause).toBe(cause);
  });

  it('works without cause', () => {
    const err = new GhostIDError('no cause', ErrorCodes.NO_KEYS);
    expect(err.cause).toBeUndefined();
  });

  it('all ErrorCodes are defined strings', () => {
    expect(Object.keys(ErrorCodes).length).toBeGreaterThan(0);
    for (const code of Object.values(ErrorCodes)) {
      expect(typeof code).toBe('string');
    }
  });
});
