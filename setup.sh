#!/usr/bin/env bash
# Local-only preparation: no sudo, curl-pipe-shell, system writes or hidden downloads.
set -Eeuo pipefail
trap 'code=$?; printf "BURHAN setup stopped at line %s (exit %s). No scan was started.\n" "$LINENO" "$code" >&2; exit "$code"' ERR
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if (( $# > 1 )); then echo 'Usage: bash setup.sh [--check]' >&2; exit 1; fi
case "${1:-}" in
  ""|--check) ;;
  *) echo 'Usage: bash setup.sh [--check]' >&2; exit 1 ;;
esac
command -v python3 >/dev/null || { echo 'Install Python 3.11+ first.' >&2; exit 1; }
python3 -B -c 'import sys,ssl,venv; assert sys.version_info >= (3,11), "Python 3.11+ required"; print("Python:",sys.version.split()[0]); print(ssl.OPENSSL_VERSION)'
for tool in git openssl; do
  command -v "$tool" >/dev/null || {
    echo "Missing $tool. On Kali: sudo apt install git python3 python3-venv openssl ca-certificates" >&2
    exit 1
  }
done
# Fails early on Windows mounts, noexec mounts and unsupported private modes.
python3 -B burhan.py preflight
if [[ "${1:-}" == --check ]]; then
  python3 -B burhan.py doctor
  echo 'Environment inspection complete; disposable probes removed, no virtual environment created.'
  exit 0
fi
if [[ -L .venv ]]; then
  echo '.venv is a symbolic link; refusing to modify or trust an external environment.' >&2
  exit 1
fi
if [[ -e .venv && ( ! -f .venv/pyvenv.cfg || ! -x .venv/bin/python ) ]]; then
  echo '.venv is incomplete or not a virtual environment. Back it up and rerun setup; no files were deleted.' >&2
  exit 1
fi
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv --without-pip .venv || {
    echo 'Could not create local environment. Install python3-venv through your package manager.' >&2
    exit 1
  }
fi
.venv/bin/python -B -c 'import sys,ssl; from pathlib import Path; assert sys.version_info >= (3,11); assert Path(sys.prefix).resolve() == Path(".venv").resolve(), "Wrong virtual environment prefix"'
.venv/bin/python -B burhan.py doctor
bash verify.sh
echo
echo 'BURHAN ready. No external scanners were downloaded or enabled.'
echo './burhan plan --policy policy.example.json'
echo 'Read README.md and set your actual authorization before any scan.'
