#!/usr/bin/env python3
"""Execute every classified runnable documentation family and retain identities."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from docs_blocks import check

ROOT=Path(__file__).resolve().parent.parent
RELEASE='e771ec647b7f26a0a09ff852886eb8a91093bc58'
RUNNERS={
    'scripts/smoke_snippets.py', 'scripts/test_docs_policies.py',
    'scripts/test_docs_examples.py', 'scripts/test_docs_evidence.py',
    'scripts/test_docs_sdk_examples.py',
}

def runner_inventory(inventory):
    required={entry['runner'] for entry in inventory.values() if entry['kind']=='runnable'}
    if required-RUNNERS:
        raise ValueError(f'unmapped runnable example runners: {sorted(required-RUNNERS)}')
    return sorted(required)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--h2h',default=os.environ.get('H2H',str(ROOT/'target/release/h2h')))
    parser.add_argument('--out',type=Path,default=ROOT/'target/docs-qualification')
    args=parser.parse_args()
    binary=Path(args.h2h).resolve()
    args.out.mkdir(parents=True,exist_ok=True)
    check()
    required=runner_inventory(json.loads((ROOT/'docs/examples/blocks.json').read_text()))
    # The CLI may be built at the docs revision; its implementation must still
    # equal the immutable v1 tree. Do not falsify its embedded build identity.
    subprocess.run(['git','diff','--exit-code',RELEASE,'--','crates','packages','Cargo.toml','Cargo.lock','package.json','package-lock.json','rulesets','library','spec','schemas'],cwd=ROOT,check=True)
    dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).strip())
    if os.environ.get('CI') and dirty:
        raise SystemExit('CI documentation qualification requires a clean source checkout')
    summary={
        'releaseCommit':RELEASE,
        'docsCommit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'dirty':dirty,
        'cli':json.loads(subprocess.check_output([str(binary),'version','--format','json'],text=True)),
        'cliSha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'runId':os.environ.get('GITHUB_RUN_ID'), 'attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),
        'requiredRunners':required,'checks':[],
    }
    commands=[
        [sys.executable,'-m','unittest','discover','-s','scripts','-p','test_export_site_docs.py'],
        [sys.executable,'scripts/test_docs_blocks.py'],
        [sys.executable,'scripts/test_docs_style.py'],
        [sys.executable,'scripts/test_qualify_docs.py'],
        [sys.executable,'scripts/test_cli_docs.py'],
        [sys.executable,'scripts/check_docs_api.py'],
        [sys.executable,'scripts/check_cli_docs.py','--h2h',str(binary)],
        *[[sys.executable,runner] for runner in required],
    ]
    for index,command in enumerate(commands):
        log=args.out/f'{index:02d}-{Path(command[1]).stem}.log'
        with log.open('w') as output:
            result=subprocess.run(command,cwd=ROOT,env={**os.environ,'H2H':str(binary)},stdout=output,stderr=subprocess.STDOUT)
        body=log.read_text()
        summary['checks'].append({'command':command,'exitCode':result.returncode,'log':log.name,
                                  'artifacts':[line for line in body.splitlines() if line.startswith('ARTIFACT ')]})
        summary['passed']=len(summary['checks'])==len(commands) and all(item['exitCode']==0 for item in summary['checks'])
        (args.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        print(f'{log.name}: exit {result.returncode}',flush=True)
        if result.returncode:
            print(body[-12000:])
            raise SystemExit(result.returncode)
    print(json.dumps(summary,indent=2))

if __name__=='__main__':
    main()
