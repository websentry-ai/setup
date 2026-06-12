#!/bin/bash
# Universal2 gate (WEB-4789): every Mach-O in the given directories must
# contain BOTH x86_64 and arm64 slices. A single thin file means an Intel
# Mac (or a Rosetta-translated process) gets a broken runtime — fail the
# whole release, listing every offender.
# Usage: lipo-gate.sh <dir> [<dir>...]
set -euo pipefail

[[ $# -ge 1 ]] || { echo "usage: $0 <dir> [<dir>...]" >&2; exit 2; }

fail=0
checked=0
while IFS= read -r -d '' f; do
  # find -type f (without -L) already excludes symlinks; the -L test is
  # belt-and-suspenders so each inode is only ever checked once.
  [[ -L "$f" ]] && continue
  if file -b "$f" | grep -q 'Mach-O'; then
    checked=$((checked + 1))
    archs="$(lipo -archs "$f" 2>/dev/null || true)"
    case "$archs" in
      *x86_64*arm64*|*arm64*x86_64*) ;;
      *)
        echo "THIN MACH-O: $f (archs: ${archs:-unreadable})"
        fail=1
        ;;
    esac
  fi
done < <(find "$@" -type f -print0)

[[ $checked -gt 0 ]] || { echo "ERROR: no Mach-O files found under: $*" >&2; exit 1; }
if [[ $fail -eq 0 ]]; then
  echo "lipo gate: $checked Mach-O files checked, all universal2."
else
  echo "lipo gate: $checked Mach-O files checked — thin Mach-O failures listed above." >&2
fi
exit $fail
