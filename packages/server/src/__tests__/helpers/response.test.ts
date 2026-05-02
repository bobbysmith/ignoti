import { describe, expect, it, vi } from 'vitest';

import { ERROR_CODES, ERROR_MESSAGES } from '../../constants';
import { sendError } from '../../helpers/response.js';

function makeMockReply() {
  const reply = { code: vi.fn(), send: vi.fn() };
  reply.code.mockReturnValue(reply);
  reply.send.mockReturnValue(reply);
  return reply;
}

describe('sendError', () => {
  it('calls reply.code() with the provided status', () => {
    const reply = makeMockReply();
    sendError(reply as never, 404, ERROR_CODES.USER_NOT_FOUND);
    expect(reply.code).toHaveBeenCalledWith(404);
  });

  it('calls reply.send() after reply.code()', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(reply.code).toHaveBeenCalledBefore(reply.send);
  });

  it('includes the error code in the response body', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(reply.send).toHaveBeenCalledWith(
      expect.objectContaining({ error: ERROR_CODES.INVALID_INPUT })
    );
  });

  it('looks up the human-readable message from ERROR_MESSAGES', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(reply.send).toHaveBeenCalledWith(
      expect.objectContaining({ message: ERROR_MESSAGES[ERROR_CODES.INVALID_INPUT] })
    );
  });

  it('every ERROR_CODE maps to a non-empty message string', () => {
    for (const code of Object.values(ERROR_CODES)) {
      expect(ERROR_MESSAGES[code], `missing message for code "${code}"`).toBeTruthy();
    }
  });

  it('omits the details key entirely when details is undefined', () => {
    const reply = makeMockReply();
    sendError(reply as never, 404, ERROR_CODES.USER_NOT_FOUND);
    const body = reply.send.mock.calls[0][0] as Record<string, unknown>;
    expect(Object.keys(body)).not.toContain('details');
  });

  it('includes details when an object is provided', () => {
    const reply = makeMockReply();
    const details = { field: 'rootPublicKey', issue: 'too short' };
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, details);
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ details }));
  });

  it('includes details when details is null (null !== undefined)', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, null);
    const body = reply.send.mock.calls[0][0] as Record<string, unknown>;
    expect(Object.keys(body)).toContain('details');
    expect(body.details).toBeNull();
  });

  it('includes details when details is a string', () => {
    const reply = makeMockReply();
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, 'extra info');
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ details: 'extra info' }));
  });

  it('includes details when details is an array', () => {
    const reply = makeMockReply();
    const details = ['err1', 'err2'];
    sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT, details);
    expect(reply.send).toHaveBeenCalledWith(expect.objectContaining({ details }));
  });

  it('returns the value of reply.send() for Fastify handler chaining', () => {
    const reply = makeMockReply();
    const result = sendError(reply as never, 400, ERROR_CODES.INVALID_INPUT);
    expect(result).toBe(reply);
  });
});
