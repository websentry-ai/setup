#!/bin/bash
# Sign every nested Mach-O in the given bundle directories individually
# (WEB-4789). Deep SIGNING is deprecated, so we walk the tree ourselves:
# innermost files first, each bundle's main executable last (its signature
# seals the bundle contents). --deep is used only on the VERIFY side, where
# it is still supported and recurses for us.
#
# Usage: sign-machos.sh <identity> <entitlements.plist> <bundle-dir> [<bundle-dir>...]
# The keychain holding <identity> must already be unlocked (CI imports the
# Developer ID Application cert into a throwaway keychain first).
set -euo pipefail

[[ $# -ge 3 ]] || { echo "usage: $0 <identity> <entitlements> <bundle-dir>..." >&2; exit 2; }
identity="$1"; entitlements="$2"; shift 2

[[ -f "$entitlements" ]] || { echo "ERROR: entitlements file not found: $entitlements" >&2; exit 1; }

for bundle in "$@"; do
  [[ -d "$bundle" ]] || { echo "ERROR: bundle dir not found: $bundle" >&2; exit 1; }
  main_exe="$bundle/$(basename "$bundle")"
  [[ -f "$main_exe" ]] || { echo "ERROR: main executable not found: $main_exe" >&2; exit 1; }

  signed=0
  # Deepest paths first so an enclosing binary is always signed after the
  # libraries it links. The main executable is excluded here and signed last.
  while IFS= read -r f; do
    [[ "$f" == "$main_exe" ]] && continue
    [[ -L "$f" ]] && continue
    if file -b "$f" | grep -q 'Mach-O'; then
      codesign --force --options runtime --timestamp \
        --entitlements "$entitlements" --sign "$identity" "$f"
      signed=$((signed + 1))
    fi
  done < <(find "$bundle" -type f | awk -F/ '{print NF"\t"$0}' | sort -rn | cut -f2-)

  codesign --force --options runtime --timestamp \
    --entitlements "$entitlements" --sign "$identity" "$main_exe"
  signed=$((signed + 1))

  # Verification: --deep recursion is fine (and recommended) here.
  codesign --verify --deep --strict --verbose=2 "$main_exe"
  echo "Signed $signed Mach-O files in $bundle and verified (--deep --strict)."
done
