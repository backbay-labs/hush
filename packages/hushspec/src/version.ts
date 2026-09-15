/**
 * HushSpec specification version support.
 *
 * Version acceptance follows core spec 2.2 (D14): an engine that supports a
 * minor version `X.Y` accepts every `X.Y.Z` document, because patch versions
 * carry only clarifications and errata. This engine implements the 0.2.0
 * semantics and also accepts 0.1.x documents (evaluated under 0.2 semantics).
 */

/** The HushSpec version this engine writes by default. */
export const HUSHSPEC_VERSION = '0.2.0';

/** Minor versions this engine accepts, as `X.Y` strings. */
export const HUSHSPEC_SUPPORTED_MINORS = ['0.1', '0.2'] as const;

/**
 * Representative full versions for each supported minor (display only; use
 * {@link isSupported} for acceptance, which accepts every patch level).
 */
export const SUPPORTED_VERSIONS = ['0.1.0', '0.2.0'] as const;

const DIGITS = /^[0-9]+$/;

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
