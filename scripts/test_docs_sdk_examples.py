#!/usr/bin/env python3
"""Execute the downloadable SDK programs in owned directories.

The runner packages the unchanged v1 implementation before running examples;
it never claims a successful registry install. Each example asserts its own
dispatch, receipt, and invalid-policy outcomes.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RELEASE = 'e771ec647b7f26a0a09ff852886eb8a91093bc58'


def artifact_identity(path):
    print(f'ARTIFACT {path.name} sha256:{hashlib.sha256(path.read_bytes()).hexdigest()} source:{RELEASE}', flush=True)


def run(command, cwd, env=None):
    subprocess.run(command, cwd=cwd, env={**os.environ, **(env or {})}, check=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--language', choices=['rust','typescript','python','go','all'], default='all')
    args=parser.parse_args()
    run(['git', 'diff', '--exit-code', RELEASE, '--', 'crates', 'packages', 'Cargo.toml', 'Cargo.lock', 'package.json', 'package-lock.json', 'rulesets', 'library'], ROOT)
    languages=['typescript','python','go','rust'] if args.language=='all' else [args.language]
    for language in languages:
        with tempfile.TemporaryDirectory(prefix=f'hush-doc-{language}-') as directory:
            work=Path(directory)
            source=ROOT/'docs/examples/sdks'/language
            if not source.is_dir():
                raise SystemExit(f'missing executable {language} example: {source}')
            shutil.copytree(source,work,dirs_exist_ok=True)
            shutil.copyfile(ROOT/'docs/examples/quickstart/policy.yaml',work/'policy.yaml')
            if language=='typescript':
                run(['npm','run','build','--workspace','@hushspec/core'],ROOT)
                package=subprocess.check_output(['npm','pack','--workspace','@hushspec/core','--pack-destination',str(work),'--json'],cwd=ROOT,text=True)
                import json
                artifact=work/json.loads(package)[0]['filename']
                artifact_identity(artifact)
                run(['npm','install','--ignore-scripts','--no-audit','--no-fund',str(artifact)],work)
                run(['node','main.mjs','policy.yaml'],work)
                run(['node','mcp.mjs','policy.yaml'],work)
                run(['node','adapters.mjs','policy.yaml'],work)
            elif language=='python':
                run([sys.executable,'-m','pip','wheel','--no-deps','--wheel-dir',str(work),str(ROOT/'packages/python')],work)
                run([sys.executable,'-m','venv',str(work/'venv')],work)
                python=work/'venv/bin/python'
                wheel=next(work.glob('hushspec-*.whl'))
                artifact_identity(wheel)
                run([str(python),'-m','pip','install',str(wheel)+'[signing]'],work)
                run([str(python),'main.py','policy.yaml'],work)
                run([str(python),'adapters.py','policy.yaml'],work)
            elif language=='go':
                # A clean archived v1 module is the distribution input; not a
                # replace pointing at a mutable SDK working directory.
                archive=subprocess.check_output(['git','archive',RELEASE,'packages/go'],cwd=ROOT)
                print(f'ARTIFACT go-module.tar sha256:{hashlib.sha256(archive).hexdigest()} source:{RELEASE}', flush=True)
                import io
                import tarfile
                with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                    tar.extractall(work/'release',filter='data')
                run(['go','mod','edit','-replace',f'github.com/backbay-labs/hush/packages/go={work}/release/packages/go'],work)
                run(['go','mod','tidy'],work)
                run(['go','run','.','policy.yaml'],work)
            else:
                run(['cargo','package','-p','hushspec','--no-verify','--allow-dirty','--locked'],ROOT)
                artifact_identity(ROOT/'target/package/hushspec-1.0.0.crate')
                import tarfile
                with tarfile.open(ROOT/'target/package/hushspec-1.0.0.crate') as tar:
                    tar.extractall(work/'release',filter='data')
                # Generated qualification manifest; shipped example manifest
                # retains the public version dependency.
                with (work/'Cargo.toml').open('a') as f:
                    f.write(f'\n[patch.crates-io]\nhushspec = {{ path = "{work}/release/hushspec-1.0.0" }}\n')
                run(['cargo','run','--quiet','--','policy.yaml'],work,{'CARGO_TARGET_DIR':str(ROOT/'target/docs-examples')})
            print(f'{language}: owned dispatch example passed', flush=True)


if __name__=='__main__':
    main()
