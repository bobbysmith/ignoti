import { describe, expect, it } from 'vitest';
import { validateString } from '@/api/validation.ts';

const MAX_STRING_LENGTH = 100;

describe('validateString', () => {
  it('returns trimmed string for valid input', () => {
    expect(validateString('  hello  ', 'field', MAX_STRING_LENGTH)).toBe('hello');
  });

  it('throws for non-string input', () => {
    expect(() => validateString(123, 'field', MAX_STRING_LENGTH)).toThrow('Invalid field');
    expect(() => validateString(null, 'field', MAX_STRING_LENGTH)).toThrow('Invalid field');
    expect(() => validateString(undefined, 'field', MAX_STRING_LENGTH)).toThrow('Invalid field');
    expect(() => validateString({}, 'field', MAX_STRING_LENGTH)).toThrow('Invalid field');
  });

  it('throws for empty string', () => {
    expect(() => validateString('', 'field', MAX_STRING_LENGTH)).toThrow('Invalid field');
  });

  it('throws for whitespace-only string', () => {
    expect(() => validateString('   ', 'field', MAX_STRING_LENGTH)).toThrow('cannot be empty');
  });

  it('throws when trimmed value exceeds maxLength', () => {
    expect(() =>
      validateString('a'.repeat(MAX_STRING_LENGTH + 1), 'myField', MAX_STRING_LENGTH)
    ).toThrow('exceeds maximum length');
  });

  it('accepts a string exactly at maxLength', () => {
    const val = 'a'.repeat(MAX_STRING_LENGTH);
    expect(validateString(val, 'field', MAX_STRING_LENGTH)).toBe(val);
  });

  it('includes the field name in error messages', () => {
    expect(() => validateString('', 'rootPublicKey', MAX_STRING_LENGTH)).toThrow('rootPublicKey');
    expect(() =>
      validateString('a'.repeat(MAX_STRING_LENGTH + 1), 'rootPublicKey', MAX_STRING_LENGTH)
    ).toThrow('rootPublicKey');
  });
});
