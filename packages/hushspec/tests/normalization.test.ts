import { describe, it, expect } from 'vitest';
import {
  hostPatternMatches,
  normalizeHost,
  normalizePath,
  pathGlobMatches,
  punycodeEncode,
} from '../src/evaluate.js';

// Host and path normalization (core spec 3.14.1, 3.14.2).

describe('normalizeHost', () => {
  it('reduces an egress target to a bare host', () => {
    const cases: Array<[string, string | undefined]> = [
      ['api.example.com', 'api.example.com'],
      ['API.EXAMPLE.COM', 'api.example.com'],
      ['api.example.com:443', 'api.example.com'],
      ['api.example.com.', 'api.example.com'],
      ['  api.example.com  ', 'api.example.com'],
      ['https://api.example.com/v1/items?x=1#frag', 'api.example.com'],
      ['https://user:pw@api.example.com:8443/', 'api.example.com'],
      ['host_name.local', 'host_name.local'],
      ['10.0.0.1', '10.0.0.1'],
    ];
    for (const [input, expected] of cases) {
      expect(normalizeHost(input), input).toBe(expected);
    }
  });

  it('encodes non-ASCII labels as IDNA A-labels', () => {
    expect(normalizeHost('BÜCHER.example')).toBe('xn--bcher-kva.example');
    expect(normalizeHost('日本語.jp')).toBe('xn--wgv71a119e.jp');
  });

  it('lowercases and keeps the brackets on an IPv6 literal', () => {
    expect(normalizeHost('[::1]:8080')).toBe('[::1]');
    expect(normalizeHost('[2001:DB8::1]')).toBe('[2001:db8::1]');
  });

  it('returns undefined for targets that are not a syntactically valid host', () => {
    for (const input of ['', '   ', 'http://', 'a..b', 'exa mple.com', '[]', '[zz::1]', 'a:b:c']) {
      expect(normalizeHost(input), input).toBeUndefined();
    }
  });
});

describe('hostPatternMatches', () => {
  it('treats `*` as exactly one label and `**` as one or more', () => {
    expect(hostPatternMatches('*.example.org', 'a.example.org')).toBe(true);
    expect(hostPatternMatches('*.example.org', 'a.b.example.org')).toBe(false);
    expect(hostPatternMatches('*.example.org', 'example.org')).toBe(false);
    expect(hostPatternMatches('**.example.org', 'a.b.example.org')).toBe(true);
    expect(hostPatternMatches('**.example.org', 'example.org')).toBe(false);
  });

  it('allows `*` inside a label', () => {
    expect(hostPatternMatches('api-*.example.org', 'api-1.example.org')).toBe(true);
    expect(hostPatternMatches('api-*.example.org', 'api-.example.org')).toBe(false);
  });

  it('matches IP literals only exactly', () => {
    expect(hostPatternMatches('10.0.*.*', '10.0.0.1')).toBe(false);
    expect(hostPatternMatches('**', '10.0.0.1')).toBe(false);
    expect(hostPatternMatches('10.0.0.1', '10.0.0.1')).toBe(true);
    expect(hostPatternMatches('[::1]', '[::1]')).toBe(true);
    expect(hostPatternMatches('[**]', '[::1]')).toBe(false);
  });

  it('normalizes the pattern the same way as the host', () => {
    expect(hostPatternMatches('API.Example.COM.', 'api.example.com')).toBe(true);
    expect(hostPatternMatches('bücher.example', 'xn--bcher-kva.example')).toBe(true);
  });
});

describe('punycodeEncode', () => {
  it('matches the RFC 3492 reference encodings', () => {
    expect(punycodeEncode('bücher')).toBe('bcher-kva');
    expect(punycodeEncode('münchen')).toBe('mnchen-3ya');
    expect(punycodeEncode('räksmörgås')).toBe('rksmrgs-5wao1o');
    expect(punycodeEncode('日本語')).toBe('wgv71a119e');
    expect(punycodeEncode('ü')).toBe('tda');
  });
});

describe('normalizePath', () => {
  it('resolves separators, dot segments and NFC', () => {
    const cases: Array<[string, string]> = [
      ['/proj/../.env', '/.env'],
      ['C:\\proj\\..\\.env', 'C:/.env'],
      ['//data//x//y', '/data/x/y'],
      ['/proj/.env/', '/proj/.env'],
      ['a/./b/', 'a/b'],
      ['/../a', '/a'],
      ['../../a', '../../a'],
      ['/', '/'],
      ['', ''],
      ['/data/cafe\u0301/x', '/data/caf\u00e9/x'],
    ];
    for (const [input, expected] of cases) {
      expect(normalizePath(input), input).toBe(expected);
    }
  });
});

describe('pathGlobMatches', () => {
  it('never lets `?` or `*` cross a separator', () => {
    expect(pathGlobMatches('/a?b', '/axb')).toBe(true);
    expect(pathGlobMatches('/a?b', '/a/b')).toBe(false);
    expect(pathGlobMatches('/a*b', '/axxb')).toBe(true);
    expect(pathGlobMatches('/a*b', '/a/x/b')).toBe(false);
  });

  it('matches zero or more leading segments with `**/`', () => {
    expect(pathGlobMatches('**/.env', '/.env')).toBe(true);
    expect(pathGlobMatches('**/.env', '/a/b/.env')).toBe(true);
    expect(pathGlobMatches('**/.env', 'C:/.env')).toBe(true);
  });

  it('treats `[` and `{` as literal characters', () => {
    expect(pathGlobMatches('/a[bc]d', '/a[bc]d')).toBe(true);
    expect(pathGlobMatches('/a[bc]d', '/abd')).toBe(false);
    expect(pathGlobMatches('/a{b,c}d', '/a{b,c}d')).toBe(true);
    expect(pathGlobMatches('/a{b,c}d', '/abd')).toBe(false);
  });
});
