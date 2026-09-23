#!/usr/bin/env python3
"""Export committed documentation blobs to hush-ui. No live-source build coupling."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', *args], cwd=root)


def safe_destination(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if not parts or any(p in ('.', '..') for p in parts) or relative.startswith('/'):
        raise ValueError(f'invalid destination path: {relative}')
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError(f'symlink destination: {path}')
    return path


def export(root: Path, site: Path, release_ref: str, docs_ref: str, *, allow_incomplete=False) -> dict:
    if site.is_symlink():
        raise ValueError(f'symlink site root: {site}')
    release = git(root, 'rev-parse', '--verify', f'{release_ref}^{{commit}}').decode().strip()
    docs = git(root, 'rev-parse', '--verify', f'{docs_ref}^{{commit}}').decode().strip()
    if git(root, 'status', '--porcelain', '--untracked-files=all', '--', 'docs/src', 'docs/examples', 'spec'):
        raise ValueError('refusing uncommitted documentation inputs')
    config_raw = (site / 'content/docs.config.json').read_bytes()
    pages = json.loads(config_raw)['pages']
    routes = [p['route'] for p in pages]
    if len(routes) != len(set(routes)):
        raise ValueError('duplicate route')
    for page in pages:
        if not re.fullmatch(r'(docs/src|spec)/[a-z0-9/-]+\.md', page['sourcePath']):
            raise ValueError(f"invalid source path: {page['sourcePath']}")

    sources: dict[str, tuple[str, str]] = {}
    for commit, prefixes in ((docs, ('docs/src/', 'docs/examples/')), (release, ('spec/',))):
        for line in git(root, 'ls-tree', '-r', commit).decode().splitlines():
            info, path = line.split('\t', 1)
            mode, kind, _ = info.split()
            selected = (path.startswith(prefixes) and
                        (not path.startswith('spec/') or path in {p['sourcePath'] for p in pages}))
            if not selected:
                continue
            if mode not in ('100644', '100755') or kind != 'blob':
                raise ValueError(f'not a regular source: {path}')
            if not re.fullmatch(r'[A-Za-z0-9_./-]+', path) or '..' in PurePosixPath(path).parts:
                raise ValueError(f'invalid source path: {path}')
            sources[path] = (commit, path)
    missing = sorted({p['sourcePath'] for p in pages} - sources.keys())
    if missing and not allow_incomplete:
        raise ValueError(f'missing registered sources: {missing}')

    files = []
    writes = []
    for path, (commit, source) in sorted(sources.items()):
        raw = git(root, 'show', f'{commit}:{source}')
        destination = safe_destination(site, f'content/upstream/{path}')
        files.append({'repo':'backbay-labs/hush', 'sourcePath':source, 'sourceCommit':commit,
                      'path':path, 'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()})
        writes.append((destination, raw))
    manifest = {'schemaVersion':1, 'releaseVersion':'1.0.0', 'releaseCommit':release,
                'docsCommit':docs, 'configSha256':hashlib.sha256(config_raw).hexdigest(),
                'pendingSources':missing, 'files':files}
    manifest_path = safe_destination(site, 'content/upstream/manifest.json')
    # Validate every target before the first write, including all parent symlinks.
    for destination, raw in writes:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    manifest_path.write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-ref', required=True)
    parser.add_argument('--docs-ref', required=True)
    parser.add_argument('--site-root', required=True, type=Path)
    parser.add_argument('--allow-incomplete', action='store_true', help='development only; release checker rejects pending sources')
    args = parser.parse_args()
    manifest = export(ROOT, args.site_root, args.release_ref, args.docs_ref, allow_incomplete=args.allow_incomplete)
    print(f"Exported {len(manifest['files'])} committed files; {len(manifest['pendingSources'])} pending sources; docs {manifest['docsCommit']}")


if __name__ == '__main__':
    main()
