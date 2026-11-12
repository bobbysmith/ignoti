import { describe, expect, it } from 'vitest';
import { canonicalRequestUrl } from '../index.js';

describe('canonicalRequestUrl', () => {
  it('keeps origin, path, and query string', () => {
    expect(canonicalRequestUrl('https://api.example.com/v1/orders?id=1&x=2')).toBe(
      'https://api.example.com/v1/orders?id=1&x=2'
    );
  });

  it('drops the fragment', () => {
    expect(canonicalRequestUrl('https://api.example.com/a?b=1#frag')).toBe(
      'https://api.example.com/a?b=1'
    );
  });

  it('normalizes host case and default ports', () => {
    expect(canonicalRequestUrl('HTTPS://API.Example.com:443/a')).toBe('https://api.example.com/a');
  });

  it('distinguishes different hosts, paths, and queries', () => {
    const base = canonicalRequestUrl('https://a.example.com/x?y=1');
    expect(canonicalRequestUrl('https://b.example.com/x?y=1')).not.toBe(base);
    expect(canonicalRequestUrl('https://a.example.com/z?y=1')).not.toBe(base);
    expect(canonicalRequestUrl('https://a.example.com/x?y=2')).not.toBe(base);
  });

  it('throws on a relative URL', () => {
    expect(() => canonicalRequestUrl('/api/feed')).toThrow();
  });
});
