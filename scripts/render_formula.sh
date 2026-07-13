#!/usr/bin/env bash
# Render Formula/h2h.rb from a tag + SHA256SUMS file. Usage: render_formula.sh <tag> <sums-file>
set -euo pipefail
tag="$1"; sums="$2"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] || {
  echo "error: invalid tag format: $tag" >&2
  exit 1
}
version="${tag#v}"
sha() {
  local result
  result="$(grep "h2h-${tag}-$1.tar.gz" "$sums" | cut -d' ' -f1 || true)"
  [ -n "$result" ] || { echo "error: no checksum line for $1" >&2; exit 1; }
  printf '%s' "$result"
}
base="https://github.com/backbay-labs/hush/releases/download/${tag}"

# Resolved as plain assignments (not inline inside the heredoc below): a
# failing `sha()` calls `exit 1` inside the $(...) subshell, and only a
# plain top-level assignment reliably propagates that subshell's non-zero
# status through `set -e`. Interpolating `$(sha ...)` directly inside the
# `cat <<EOF` heredoc would NOT trigger a script failure -- the substitution
# error is silently swallowed and an empty string is spliced into the
# formula instead.
sha_aarch64_apple_darwin="$(sha aarch64-apple-darwin)"
sha_x86_64_apple_darwin="$(sha x86_64-apple-darwin)"
sha_aarch64_unknown_linux_gnu="$(sha aarch64-unknown-linux-gnu)"
sha_x86_64_unknown_linux_gnu="$(sha x86_64-unknown-linux-gnu)"

cat <<EOF
class H2h < Formula
  desc "CLI for validating, testing, and enforcing HushSpec policies"
  homepage "https://github.com/backbay-labs/hush"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "${base}/h2h-${tag}-aarch64-apple-darwin.tar.gz"
      sha256 "${sha_aarch64_apple_darwin}"
    end
    on_intel do
      url "${base}/h2h-${tag}-x86_64-apple-darwin.tar.gz"
      sha256 "${sha_x86_64_apple_darwin}"
    end
  end

  on_linux do
    on_arm do
      url "${base}/h2h-${tag}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "${sha_aarch64_unknown_linux_gnu}"
    end
    on_intel do
      url "${base}/h2h-${tag}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "${sha_x86_64_unknown_linux_gnu}"
    end
  end

  def install
    bin.install Dir["h2h-*/h2h"].first || "h2h"
  end

  test do
    system "#{bin}/h2h", "--version"
  end
end
EOF
