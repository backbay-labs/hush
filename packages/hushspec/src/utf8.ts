/**
 * UTF-8 measurements.
 *
 * Every byte budget HushSpec defines -- a document's maximum size (core spec
 * 2.4), a detector's `max_scan_bytes` / `max_input_bytes` (detection spec 3),
 * `code_execution.max_scan_bytes` (core spec 3.12), a receipt's
 * `action.content_size` (receipt spec 4.4) -- counts UTF-8 bytes. JavaScript
 * strings are UTF-16, so those budgets are measured against the encoded form
 * rather than `string.length`.
 */

/** The number of UTF-8 bytes `value` encodes to. */
export function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}

/**
 * `content` truncated to at most `limit` UTF-8 bytes, cut on a character
 * boundary so the result is always well-formed text.
 */
export function truncateUtf8(content: string, limit: number): string {
  const bytes = new TextEncoder().encode(content);
  if (bytes.length <= limit) return content;
  let end = limit;
  // UTF-8 continuation bytes are `10xxxxxx`; back off until the byte at the
  // cut point starts a character rather than continuing one.
  while (end > 0 && (bytes[end]! & 0xc0) === 0x80) {
    end -= 1;
  }
  return new TextDecoder().decode(bytes.subarray(0, end));
}
