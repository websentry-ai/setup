# WEB-4785 — PyInstaller spike: claude-code hook as a self-contained macOS binary

Goal: prove the existing `claude-code/hooks/unbound.py` can ship as a
PyInstaller `--onedir` bundle that runs on Macs with **no python3 and no
Xcode Command Line Tools**, in both Intel and Apple Silicon fleets, without
regressing hook latency.

## Build toolchain

| Component | Choice | Why |
|---|---|---|
| Interpreter | python.org CPython **3.12.10** universal2 (`python-3.12.10-macos11.pkg`) | Last 3.12.x with a macOS binary installer; framework build ships fat (x86_64+arm64) interpreter, libpython, and OpenSSL |
| PyInstaller | **6.20.0**, `--onedir --target-arch universal2` | onedir avoids the onefile per-run extraction penalty; universal2 bootloaders ship in the macOS wheel |
| Spec file | `binary/unbound-hook-spike.spec` | committed; `pyinstaller binary/unbound-hook-spike.spec` reproduces the bundle |

Notes for build machines:
- The python.org pkg payload can be extracted and relocated without sudo
  (`pkgutil --expand-full`), but every Mach-O that hardcodes
  `/Library/Frameworks/Python.framework/...` install names must be rewritten
  with `install_name_tool` and ad-hoc re-signed (`codesign -f -s -`),
  including `lib/*.dylib` and `lib-dynload/_ssl`/`_hashlib` (otherwise pip
  has no SSL). A normal system install of the pkg avoids all of this.
- CI should install the pkg normally and build with
  `pyinstaller binary/unbound-hook-spike.spec`.

## Gate results

### 1. universal2 — PASS

`lipo -archs` on **every** Mach-O in `dist/unbound-hook-spike/`:
46/46 files report `x86_64 arm64`. No thin binaries.

### 2. Behavior parity — PASS (sampled)

Same stdin event JSON → byte-identical stdout between
`python3.12 claude-code/hooks/unbound.py` and the frozen binary for:
PreToolUse (Bash), UserPromptSubmit, Stop, SessionEnd, empty stdin,
malformed JSON. (Network-path parity is exercised in WEB-4786's
CLI-boundary tests; the spike used a sandboxed `$HOME` with no API key so
both paths take the no-network short-circuit.)

### 3. Warm latency — PASS (p95 109ms ≤ 120ms)

hyperfine, 100 runs + 10 warmups, `-N` (no shell) with `--input` piping a
representative PreToolUse Bash event; sandboxed `$HOME` (no API key → no
gateway round-trip, measures pure hook overhead). Apple M4 Max, 36GB,
macOS 26.5:

| Variant | p50 | p95 | min | max |
|---|---|---|---|---|
| frozen binary (onedir) | 101.3ms | **109.0ms** | 80.8ms | 113.2ms |
| python3.12 script (same machine) | 82.9ms | 93.7ms | 67.7ms | 206.8ms |
| PyInstaller hello-world floor | 65.0ms | 70.1ms | 53.6ms | — |

The binary adds ~15–18ms over the interpreted path (bootloader + dyld of
the bundled libpython). Measurement caveats:
- An earlier run *through a shell* showed p95 160ms — shell spawn and
  machine noise, not the binary. Always benchmark with `-N`/`--input`.
- Fleet hardware (older Intel/M1) will be slower in absolute terms for
  both paths; the *delta* is what the binary owns.

Untapped headroom if ever needed: `--optimize 2`, pruning default
collected modules. Not applied — keeping the spike unmodified.

### 4. First-exec Gatekeeper/syspolicyd stall — measured, ~3.8s

First execution after the bundle lands on **new inodes** (fresh copy of the
dist dir), 3 trials:

| Trial | first exec | second exec |
|---|---|---|
| 1 | 3870ms | 174ms |
| 2 | 3727ms | 177ms |
| 3 | 3747ms | 171ms |

This is syspolicyd scanning each new Mach-O inode on first launch (ad-hoc
signed, not notarized). Implications:
- The stall recurs **on every install/update** (new inodes), then never again.
- Mitigation: the pkg postinstall (WEB-4792) pre-warms each binary with
  `--version` before flipping the `current` symlink, so the stall is
  absorbed during MDM install, not on the user's first prompt — which is
  why `unbound-hook --version` must exit fast without reading stdin.
  Notarization (separate cert track) should shrink it further.
- No codesigning/notarization attempted in this spike per ticket scope.

## Decision

universal2 worked on the first build — **no per-arch fallback needed**.
Bundle size: 40MB onedir. Proceed to WEB-4786 (single `unbound-hook` CLI
wrapping all four tools' hooks + setup/backfill/clear).
