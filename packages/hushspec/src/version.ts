/**
 * HushSpec specification version support.
 *
 * Version acceptance follows core spec 2.2: an engine that supports a
 * minor version `X.Y` accepts every `X.Y.Z` document, because patch versions
 * carry only clarifications and errata. This engine implements the 1.0.0
 * semantics, which are identical to 0.2.0, and also accepts 0.1.x and 0.2.x
 * documents (core spec 10).
 */

/** The HushSpec version this engine writes by default. */
export const HUSHSPEC_VERSION = '1.0.0';

/**
 * This package's own identity, as a receipt log's `sdk` member records it
 * (spec/hushspec-log.md section 6). Independent of {@link HUSHSPEC_VERSION},
 * which is the *specification* version the engine implements: the two are
 * versioned separately (core spec 10.3) and this release is the one where
 * they happen to coincide.
 *
 * `tests/version.test.ts` pins {@link SDK_VERSION} to `package.json`.
 */
export const SDK_NAME = '@hushspec/core';

/** @see {@link SDK_NAME} */
export const SDK_VERSION = '1.0.0';

/** Minor versions this engine accepts, as `X.Y` strings. */
export const HUSHSPEC_SUPPORTED_MINORS = ['0.1', '0.2', '1.0'] as const;

/**
 * Representative full versions for each supported minor (display only; use
 * {@link isSupported} for acceptance, which accepts every patch level).
 *
 * Spelled identically in every HushSpec SDK, so they all name one constant.
 */
export const HUSHSPEC_SUPPORTED_VERSIONS = ['0.1.0', '0.2.0', '1.0.0'] as const;

/**
 * This package's original name for {@link HUSHSPEC_SUPPORTED_VERSIONS}, kept
 * so existing callers keep working.
 */
export const SUPPORTED_VERSIONS = HUSHSPEC_SUPPORTED_VERSIONS;

const DIGITS = /^[0-9]+$/;

/**
 * The MAJOR component of a well-formed `X.Y.Z` version string, or `undefined`
 * when the string is not one.
 *
 * The document format is versioned by its major component: the 1.0 format
 * differs from 0.x only in the constraints it places on a document (core spec
 * 10), so a constraint introduced with 1.0 is gated on this rather than on the
 * minor an engine happens to support.
 */
export function majorVersion(version: string): number | undefined {
  const parts = version.split('.');
  if (parts.length !== 3) return undefined;
  if (!parts.every(part => DIGITS.test(part))) return undefined;
  // A major that does not fit an unsigned 32-bit integer names no format any
  // SDK could support, and every SDK applies the same bound.
  if (parts[0]!.length > 10) return undefined;
  const major = Number(parts[0]);
  return major <= 0xffff_ffff ? major : undefined;
}

/**
 * The `X.Y` minor of a well-formed, supported version string, or `undefined`
 * when the version is malformed or its minor is not supported.
 */
export function supportedMinor(version: string): string | undefined {
  const parts = version.split('.');
  if (parts.length !== 3) return undefined;
  if (!parts.every(part => DIGITS.test(part))) return undefined;
  const minor = `${parts[0]}.${parts[1]}`;
  return (HUSHSPEC_SUPPORTED_MINORS as readonly string[]).includes(minor) ? minor : undefined;
}

/**
 * Whether `version` is a well-formed `X.Y.Z` string whose minor version this
 * engine supports. Any patch level of a supported minor is accepted.
 */
export function isSupported(version: string): boolean {
  return supportedMinor(version) != null;
}
