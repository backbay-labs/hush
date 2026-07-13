#!/usr/bin/env bash
# Render Formula/h2h.rb from a tag + SHA256SUMS file. Usage: render_formula.sh <tag> <sums-file>
set -euo pipefail
tag="$1"; sums="$2"
version="${tag#v}"
sha() { grep "h2h-${tag}-$1.tar.gz" "$sums" | cut -d' ' -f1; }
base="https://github.com/backbay-labs/hush/releases/download/${tag}"

cat <<EOF
class H2h < Formula
  desc "CLI for validating, testing, and enforcing HushSpec policies"
  homepage "https://github.com/backbay-labs/hush"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "${base}/h2h-${tag}-aarch64-apple-darwin.tar.gz"
      sha256 "$(sha aarch64-apple-darwin)"
    end
    on_intel do
      url "${base}/h2h-${tag}-x86_64-apple-darwin.tar.gz"
      sha256 "$(sha x86_64-apple-darwin)"
    end
  end

  on_linux do
    on_arm do
      url "${base}/h2h-${tag}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha aarch64-unknown-linux-gnu)"
    end
    on_intel do
      url "${base}/h2h-${tag}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha x86_64-unknown-linux-gnu)"
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
