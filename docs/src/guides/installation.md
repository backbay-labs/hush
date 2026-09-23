# Installation

Install the `h2h` CLI for policy authoring and verification. Install an SDK
inside the runtime that will enforce decisions.

## CLI: macOS and Linux

The rootless installer supports macOS and glibc Linux on x64 and ARM64.
It requires `curl`, `tar`, `mktemp`, `awk`, and either `sha256sum` or
`shasum`.

```sh
curl -fsSL https://hushspec.org/install.sh -o install-h2h.sh
sh install-h2h.sh --version v1.0.0
export PATH="$HOME/.local/bin:$PATH"
h2h --version
```

Read the script before running it. It downloads the version-pinned GitHub
archive, checks SHA-256, and installs to `~/.local/bin` without sudo or profile
edits. Use `--dir /absolute/path` to select another directory. Unsupported
platforms receive manual instructions; musl/Alpine is not this binary's glibc target.

## Package managers

| Channel | Install v1 | Requirement |
| --- | --- | --- |
| Homebrew | `brew install backbay-labs/tap/h2h` | macOS or Linux; tap formula tracks its published version |
| npm | `npm install -g @hushspec/cli@1.0.0` | Supported Node installation and release platform |
| One-off npm | `npx @hushspec/cli@1.0.0 --version` | No global install |
| Cargo | `cargo install hushspec-cli --version 1.0.0 --locked` | Rust 1.88+ and native build tools |

The installed command is `h2h`, not `hushspec`. Check `command -v h2h`
and `h2h version` if an older copy is first on PATH.

## Prebuilt binaries and Windows

Download the matching archive and `SHA256SUMS` from the
[v1.0.0 release](https://github.com/backbay-labs/hush/releases/tag/v1.0.0).

| OS | Release target |
| --- | --- |
| Linux x64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Intel | `x86_64-apple-darwin` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| Windows x64 | `x86_64-pc-windows-msvc` |

Compare the archive hash against its exact filename's entry before extracting.
On Windows, use `Get-FileHash -Algorithm SHA256`, extract the archive, and put
`h2h.exe` in a directory on your user PATH. Do not compare only a partial hash.

Checksums detect corruption relative to the downloaded checksum file. Verify
GitHub artifact provenance for an additional repository/build-identity check:

```sh
gh attestation verify h2h-v1.0.0-aarch64-apple-darwin.tar.gz --repo backbay-labs/hush
```

Replace the filename with the archive you actually downloaded.

## Container

From a directory containing `policy.yaml`:

```sh
docker run --rm --network none -v "$PWD:/work:ro" -w /work \
  ghcr.io/backbay-labs/h2h:v1.0.0 validate --strict policy.yaml
```

Mount only the files needed for validation. A CLI container validates policies;
it does not automatically contain your separate agent process.

## Language SDKs

| Language | Install | Runtime floor |
| --- | --- | --- |
| Rust | `cargo add hushspec@1.0.0` | Rust 1.88 |
| TypeScript | `npm install @hushspec/core@1.0.0` | Node 18 |
| Python | `python -m pip install 'hushspec==1.0.0'` | Python 3.10 |
| Go | `go get github.com/backbay-labs/hush/packages/go@v1.0.0` | Go 1.22 |

Rust signing needs the `signing` Cargo feature; bounded HTTPS loading needs
`http`. Python signing needs `hushspec[signing]==1.0.0`. These SDK runtime
floors are separate from the documentation website's Node 20.9 toolchain.

## Update or uninstall

Re-run the installer with an explicit published version to replace that binary.
For a rootless install, remove only `~/.local/bin/h2h` to uninstall; leave policy
and evidence files intact. Package-manager installations should be updated or
removed by the same manager: `brew upgrade h2h`, `brew uninstall h2h`,
`npm uninstall -g @hushspec/cli`, or `cargo uninstall hushspec-cli`.

Before upgrading a runtime, test policy decisions, signatures, and receipt
consumers together. See [migration](migration-v1.md), then [quickstart](getting-started.md).
