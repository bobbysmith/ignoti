import { describe, expect, it } from 'vitest';
import { canonicalJson } from '../index.js';

describe('canonicalJson', () => {
  it('sorts object keys alphabetically', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it('sorts nested object keys alphabetically', () => {
    expect(canonicalJson({ z: { b: 1, a: 2 } })).toBe('{"z":{"a":2,"b":1}}');
  });

  it('produces the same output regardless of construction order', () => {
    const a = canonicalJson({ sessionId: 'abc', iat: 123, path: '/api/devices' });
    const b = canonicalJson({ path: '/api/devices', sessionId: 'abc', iat: 123 });
    expect(a).toBe(b);
  });

  it('handles arrays by preserving element order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('recursively sorts keys inside array elements', () => {
    expect(canonicalJson([{ b: 1, a: 2 }])).toBe('[{"a":2,"b":1}]');
  });

  it('handles string primitives', () => {
    expect(canonicalJson('hello')).toBe('"hello"');
  });

  it('handles number primitives', () => {
    expect(canonicalJson(42)).toBe('42');
  });

  it('handles boolean primitives', () => {
    expect(canonicalJson(true)).toBe('true');
  });

  it('handles null', () => {
    expect(canonicalJson(null)).toBe('null');
  });

  it('handles empty object', () => {
    expect(canonicalJson({})).toBe('{}');
  });

  it('handles empty array', () => {
    expect(canonicalJson([])).toBe('[]');
  });
});
