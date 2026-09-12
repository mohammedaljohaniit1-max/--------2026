#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PYTHON=python3
[[ ! -x .venv/bin/python ]] || PYTHON="$ROOT/.venv/bin/python"
bash -n setup.sh verify.sh burhan
"$PYTHON" -B - <<'PY'
from pathlib import Path
for path in sorted(Path('.').glob('*.py')):
    compile(path.read_text(), str(path), 'exec')
print('Python and shell syntax: PASS')
PY
"$PYTHON" -B -m unittest -v test_burhan test_osint test_programs test_setup
"$PYTHON" -B burhan.py --version
"$PYTHON" -B burhan.py preflight >/dev/null
"$PYTHON" -B burhan.py plan --policy policy.example.json >/dev/null
"$PYTHON" -B burhan.py osint --help >/dev/null
"$PYTHON" -B burhan.py programs plan all >/dev/null
echo 'PASS: local behavior, safety controls, parsers and CLI. No public targets scanned.'
