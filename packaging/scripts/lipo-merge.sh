#!/bin/bash
# Merge two single-arch bundle trees into one universal2 tree (WEB-4804).
#
# Nuitka 2.8.x (the last Apache-2.0 release) cannot emit universal binaries
# directly: --macos-target-arch=universal exits with "Cannot create universal
# macOS binaries (yet), please pick an arch and create two binaries." This is
# that documented fallback: build arm64 and x86_64 separately from the SAME
# universal2 CPython, then lipo -create every Mach-O pairwise. The existing
# lipo gate (lipo-gate.sh) still runs on the merged output afterwards.
#
# Usage: lipo-merge.sh <arm64-dir> <x86_64-dir> <out-dir>
# The two input trees must contain the same file set; non-Mach-O files must
# be byte-identical across the two builds (anything else means the builds
# diverged and the artifact cannot be trusted — fail, never guess).
set -euo pipefail

[[ $# -eq 3 ]] || { echo "usage: $0 <arm64-dir> <x86_64-dir> <out-dir>" >&2; exit 2; }
arm_dir="$1"; x86_dir="$2"; out_dir="$3"

[[ -d "$arm_dir" ]] || { echo "ERROR: arm64 dir not found: $arm_dir" >&2; exit 1; }
[[ -d "$x86_dir" ]] || { echo "ERROR: x86_64 dir not found: $x86_dir" >&2; exit 1; }
[[ -e "$out_dir" ]] && { echo "ERROR: out dir already exists: $out_dir" >&2; exit 1; }

list_tree() { (cd "$1" && find . \( -type f -o -type l \) | LC_ALL=C sort); }

arm_list="$(list_tree "$arm_dir")"
x86_list="$(list_tree "$x86_dir")"
if [[ "$arm_list" != "$x86_list" ]]; then
  echo "ERROR: arch builds produced different file sets:" >&2
  diff <(echo "$arm_list") <(echo "$x86_list") >&2 || true
  exit 1
fi

merged=0
while IFS= read -r rel; do
  src_a="$arm_dir/$rel"
  src_x="$x86_dir/$rel"
  dest="$out_dir/$rel"
  mkdir -p "$(dirname "$dest")"

  # Symlink/regular-file parity (WEB-4804, L1): a path that is a symlink in
  # one arch tree and a regular file in the other is a real build divergence.
  # Without this check the asymmetry is lost — readlink on the non-symlink
  # side returns empty (confusing error), or the regular-file-vs-symlink case
  # silently follows the symlink through cmp/file/lipo. Fail closed, name the
  # path, before any branch below assumes both sides share a type.
  if [[ -L "$src_a" || -L "$src_x" ]] && ! { [[ -L "$src_a" ]] && [[ -L "$src_x" ]]; }; then
    echo "ERROR: symlink/regular-file divergence for $rel: arm64 is $( [[ -L "$src_a" ]] && echo symlink || echo regular-file ), x86_64 is $( [[ -L "$src_x" ]] && echo symlink || echo regular-file )" >&2
    exit 1
  fi

  if [[ -L "$src_a" ]]; then
    target_a="$(readlink "$src_a")"
    target_x="$(readlink "$src_x")"
    [[ "$target_a" == "$target_x" ]] || {
      echo "ERROR: symlink target mismatch for $rel: '$target_a' vs '$target_x'" >&2
      exit 1
    }
    ln -s "$target_a" "$dest"
  elif file -b "$src_a" | grep -q 'Mach-O'; then
    lipo -create "$src_a" "$src_x" -output "$dest"
    perm_a="$(stat -f '%Lp' "$src_a")"
    perm_x="$(stat -f '%Lp' "$src_x")"
    [[ "$perm_a" == "$perm_x" ]] || { echo "ERROR: permission mismatch for Mach-O $rel: arm64 $perm_a vs x86_64 $perm_x" >&2; exit 1; }
    chmod "$perm_a" "$dest"
    merged=$((merged + 1))
  else
    cmp -s "$src_a" "$src_x" || {
      echo "ERROR: non-Mach-O file differs between arch builds: $rel" >&2
      exit 1
    }
    cp -p "$src_a" "$dest"
  fi
done <<< "$arm_list"

[[ $merged -gt 0 ]] || { echo "ERROR: no Mach-O files merged under $arm_dir" >&2; exit 1; }
echo "lipo-merge: $merged Mach-O files merged into $out_dir"
