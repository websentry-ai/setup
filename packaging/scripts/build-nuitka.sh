#!/bin/bash
# Build the unbound-hook + unbound-discovery onedir bundles with Nuitka
# --standalone (WEB-4804: EDR bake-off vs the default PyInstaller path).
#
# Cross-OS: on macOS this builds universal2 (per-arch + lipo merge); on Linux
# it builds a native single-arch standalone (no --macos-target-arch, no lipo).
# The Linux release lane uses this as its ONLY builder — there is no PyInstaller
# Linux path.
#
# ADDITIVE: this is an alternative builder behind the workflow's
# builder=nuitka input. The PyInstaller path stays canonical and untouched;
# output layout here is contract-identical (dist/<name>/<name>) so the
# existing lipo gate, per-Mach-O signing, smoke test, and pkg steps run on
# Nuitka output unchanged.
#
# Deliberate choices:
#   * --standalone (onedir), NEVER --onefile — onefile self-extracts to a
#     temp dir at runtime, which is exactly the EDR "packer" heuristic this
#     bake-off exists to avoid, and it would also break per-file codesign.
#   * Nuitka 2.8.x only — the last Apache-2.0 series (4.0+ is AGPLv3 with a
#     commercial tier we must not use). Pinned by hash in
#     requirements-nuitka-build.txt.
#   * universal2 via per-arch builds + lipo-merge.sh: Nuitka 2.8 hard-rejects
#     --macos-target-arch=universal ("Cannot create universal macOS binaries
#     (yet), please pick an arch and create two binaries"), so we do exactly
#     that from the same universal2 CPython. lipo-gate.sh still asserts the
#     merged result.
#   * unbound-hook compiles binary/src/unbound_hook from source with the
#     vendored module data files and hidden stdlib imports derived from
#     binary/unbound-hook.spec — one source of truth, so the Nuitka artifact
#     cannot drift from the PyInstaller contract.
#   * --deployment: release binaries must not carry Nuitka's dev-time guard
#     rails (fork-bomb detection etc.); behavior must match the PyInstaller
#     artifact as closely as possible.
#   * zero Python source changes — packaging/nuitka/unbound_hook_entry.py is
#     a build-only shim that provides the sys.frozen/sys._MEIPASS contract
#     PyInstaller's bootloader provides; the discovery entry compiles as-is.
#
# Usage: build-nuitka.sh <dist-dir>
# Env:
#   NUITKA_PYTHON          python with the hash-pinned Nuitka toolchain
#                          (default ./.build-venv-nuitka/bin/python, as
#                          created by the release workflow)
#   UNBOUND_DISCOVERY_SRC  coding-discovery-tool checkout at the locked SHA;
#                          absent -> PLACEHOLDER discovery (dry-run only,
#                          mirrors the PyInstaller fallback spec)
#   NUITKA_ARCHS           default "arm64 x86_64" (merged universal2);
#                          a single arch skips the merge — local proof
#                          builds only, CI's lipo gate rejects thin output
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 <dist-dir>" >&2; exit 2; }
dist_out="$1"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # packaging/scripts
PKG="$(dirname "$HERE")"                                # packaging
ROOT="$(dirname "$PKG")"                                # repo root
BUILD="$PKG/build/nuitka"

log() { echo "[build-nuitka] $*"; }
die() { echo "[build-nuitka] ERROR: $*" >&2; exit 1; }

PYTHON="${NUITKA_PYTHON:-$ROOT/.build-venv-nuitka/bin/python}"
command -v "$PYTHON" >/dev/null || die "build python not found: $PYTHON"

# --- Toolchain assert: installed Nuitka must match the hash-pinned version ---
pinned="$(sed -n 's/^nuitka==\([0-9A-Za-z.]*\).*/\1/p' "$PKG/requirements-nuitka-build.txt")"
[[ -n "$pinned" ]] || die "no nuitka pin found in requirements-nuitka-build.txt"
actual="$("$PYTHON" -m nuitka --version | head -n 1)"
[[ "$actual" == "$pinned" ]] || die "installed Nuitka is $actual, pin is $pinned"
# The free Apache-2.0 tier reports 'Commercial: None'; anything else means a
# commercial Nuitka leaked into the toolchain, which we must not ship with.
"$PYTHON" -m nuitka --version | grep -qx "Commercial: None" || \
    die "Nuitka does not report 'Commercial: None' — only free Apache-2.0 Nuitka is allowed"
log "nuitka $actual (hash-pinned, free tier)"

archs="${NUITKA_ARCHS:-arm64 x86_64}"
log "target archs: $archs"

rm -rf "$BUILD"
mkdir -p "$BUILD" "$dist_out"

# --- Derive unbound-hook inputs from the canonical PyInstaller spec ----------
# binary/unbound-hook.spec's VENDORED (module source data files) and HIDDEN
# (stdlib imports of those data files) lists are the contract; parse them
# instead of duplicating them so the two builders cannot drift.
hook_flags_file="$BUILD/hook-flags.txt"
"$PYTHON" - "$ROOT/binary/unbound-hook.spec" > "$hook_flags_file" <<'PYEOF'
import ast
import os
import sys

spec_path = sys.argv[1]
spec_dir = os.path.dirname(spec_path)
tree = ast.parse(open(spec_path).read())

vendored = hidden = None
for node in tree.body:
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ):
        if node.targets[0].id == "VENDORED":
            vendored = ast.literal_eval(node.value)
        elif node.targets[0].id == "HIDDEN":
            hidden = ast.literal_eval(node.value)

if vendored is None or hidden is None:
    raise SystemExit("VENDORED/HIDDEN not found in %s" % spec_path)

for src, dest_dir in vendored:
    # spec datas are (source-relative-to-spec, dest_dir); Nuitka wants
    # source=dest with the full destination file path.
    src_path = os.path.normpath(os.path.join(spec_dir, src))
    dest_path = os.path.join(dest_dir, os.path.basename(src))
    print("--include-data-files=%s=%s" % (src_path, dest_path))

for module in hidden:
    if module == "winreg":  # Windows-only stdlib; cannot resolve on the macOS
        continue            # build host, so Nuitka can't --include-module it.
    print("--include-module=%s" % module)
PYEOF

hook_flags=()
while IFS= read -r line; do hook_flags+=("$line"); done < "$hook_flags_file"
log "derived ${#hook_flags[@]} hook flags from binary/unbound-hook.spec"

# --- Discovery inputs: pinned checkout, or placeholder for dry-runs ----------
if [[ -n "${UNBOUND_DISCOVERY_SRC:-}" ]]; then
  entrypoint="$(sed -n 's/^SOURCE_ENTRYPOINT=//p' "$PKG/discovery.lock")"
  [[ -f "$UNBOUND_DISCOVERY_SRC/$entrypoint" ]] || \
      die "UNBOUND_DISCOVERY_SRC missing $entrypoint"
  discovery_entry="$PKG/unbound_discovery_entry.py"
  discovery_pythonpath="$UNBOUND_DISCOVERY_SRC/scripts"
  # Mirrors the PyInstaller spec excludes (["tkinter","test","unittest",
  # "pydoc_data"]) one-for-one so the EDR-scored artifact surface matches the
  # canonical builder (WEB-4804, D). Also drops the detector package's own
  # test subpackage.
  discovery_flags=(
    "--include-package=coding_discovery_tools"
    "--nofollow-import-to=coding_discovery_tools.test"
    "--nofollow-import-to=tkinter"
    "--nofollow-import-to=test"
    "--nofollow-import-to=unittest"
    "--nofollow-import-to=pydoc_data"
  )
else
  log "WARNING: no UNBOUND_DISCOVERY_SRC — building PLACEHOLDER unbound-discovery (dry-run only)"
  discovery_entry="$PKG/placeholder/unbound_discovery_main.py"
  discovery_pythonpath=""
  discovery_flags=()
fi

# --- Build one binary: per-arch Nuitka standalone, then universal2 merge -----
build_bundle() {
  local name="$1" entry="$2" pythonpath="$3"; shift 3
  local extra_flags=("$@")
  local entry_base arch_dists=() arch
  entry_base="$(basename "$entry" .py)"

  # Linux: native single-arch standalone. No --macos-target-arch (Nuitka
  # rejects it off-macOS) and no lipo merge. Nuitka uses patchelf for RPATH
  # (the build job installs it); --assume-yes-for-downloads lets it fetch any
  # other helper non-interactively.
  if [[ "$(uname -s)" == "Linux" ]]; then
    log "building $name (linux native) from $entry"
    PYTHONPATH="$pythonpath" "$PYTHON" -m nuitka \
      --standalone \
      --deployment \
      --static-libpython=no \
      --assume-yes-for-downloads \
      --output-dir="$BUILD/$name" \
      --output-filename="$name" \
      ${extra_flags[@]+"${extra_flags[@]}"} \
      "$entry"
    [[ -x "$BUILD/$name/$entry_base.dist/$name" ]] || die "$name: no executable produced"
    rm -rf "${dist_out:?}/$name"
    cp -R "$BUILD/$name/$entry_base.dist" "$dist_out/$name"
    [[ -x "$dist_out/$name/$name" ]] || die "$name: bundle assembly failed"
    log "built $dist_out/$name"
    return
  fi

  # macOS: per-arch builds + universal2 lipo merge (unchanged).
  # shellcheck disable=SC2086  # word-splitting the arch list is intended
  for arch in $archs; do
    log "building $name ($arch) from $entry"
    PYTHONPATH="$pythonpath" "$PYTHON" -m nuitka \
      --standalone \
      --deployment \
      --static-libpython=no \
      --macos-target-arch="$arch" \
      --output-dir="$BUILD/$name/$arch" \
      --output-filename="$name" \
      ${extra_flags[@]+"${extra_flags[@]}"} \
      "$entry"
    [[ -x "$BUILD/$name/$arch/$entry_base.dist/$name" ]] || \
        die "$name ($arch): no executable produced"
    arch_dists+=("$BUILD/$name/$arch/$entry_base.dist")
  done

  rm -rf "${dist_out:?}/$name"
  if [[ ${#arch_dists[@]} -eq 2 ]]; then
    "$HERE/lipo-merge.sh" "${arch_dists[0]}" "${arch_dists[1]}" "$dist_out/$name"
  else
    log "single arch requested — skipping universal2 merge (local proof build)"
    cp -R "${arch_dists[0]}" "$dist_out/$name"
  fi
  [[ -x "$dist_out/$name/$name" ]] || die "$name: bundle assembly failed"
  log "built $dist_out/$name"
}

build_bundle "unbound-hook" "$PKG/nuitka/unbound_hook_entry.py" \
    "$ROOT/binary/src" "${hook_flags[@]}"
build_bundle "unbound-discovery" "$discovery_entry" \
    "$discovery_pythonpath" ${discovery_flags[@]+"${discovery_flags[@]}"}

log "done — run lipo-gate.sh + smoke-test.sh on $dist_out next (CI does)"
