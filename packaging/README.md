# macOS runtime packaging (Non-Python MDM Rollout)

Everything the `release-macos-runtime` workflow needs to turn a
`runtime-v*` tag into a signed, notarized, stapled pkg + tar.gz on S3 and a
GitHub Release. Tickets: WEB-4789 (pipeline), WEB-4791 (onboard.sh
template), WEB-4792 (pkg payload).

## Layout

| Path | What |
|---|---|
| `versions.env` | Pinned python.org universal2 CPython (URL + sha256), pkg identifier, install prefix, daemon label |
| `requirements-build.txt` | Hash-pinned PyInstaller toolchain, canonical from WEB-4787 (`pip install --require-hashes --no-deps`) |
| `discovery.lock` | KEY=VALUE source pin, canonical from WEB-4787 (`SOURCE_SHA` is checked out into `./discovery-src`; `PYTHON_VERSION`/`PYINSTALLER_VERSION` are asserted against the installed toolchain) |
| `unbound-discovery.spec` + `unbound_discovery_entry.py` + `build-discovery.sh` | **Canonical** discovery bundle build (WEB-4787); CI invokes the spec with `UNBOUND_DISCOVERY_SRC=./discovery-src` |
| `specs/*.spec` | `unbound-hook.spec` is a **placeholder** until the WEB-4786 binary lands; `specs/unbound-discovery.spec` is a dry-run-only fallback for tokenless `workflow_dispatch` runs. Bundle names, onedir COLLECT layout, and `target_arch='universal2'` are the pipeline contract |
| `requirements-nuitka-build.txt` + `nuitka/` + `scripts/build-nuitka.sh` + `scripts/lipo-merge.sh` | **Alternative Nuitka builder** (WEB-4804 EDR bake-off, `workflow_dispatch` `builder=nuitka` only — tag releases always use PyInstaller). Nuitka pinned to 2.8.x, the last Apache-2.0 series. `--standalone` only, never `--onefile` (onefile's self-extract-to-temp is the EDR "packer" pattern the bake-off exists to avoid). Nuitka 2.8 cannot emit universal binaries, so the script builds arm64 + x86_64 from the same universal2 CPython and `lipo -create`-merges them; output layout is contract-identical (`dist/<name>/<name>`), so the lipo gate, per-Mach-O signing, smoke test, and pkg stages run unchanged. `unbound-hook` builds the real `binary/src` package — vendored data files and hidden imports are parsed from `binary/unbound-hook.spec` so the two builders cannot drift; `nuitka/unbound_hook_entry.py` is a build-only shim supplying the `sys.frozen`/`sys._MEIPASS` contract PyInstaller's bootloader provides |
| `placeholder/*.py` | Stdlib-only entry points so the pipeline builds/signs/smokes end-to-end today |
| `scripts/` | Build steps factored out of the workflow so they're shellcheckable and runnable locally |
| `pkg/postinstall` | Pre-warms both binaries (Gatekeeper first-exec) **before** flipping `current`, bootstraps the LaunchDaemon, sets up `/var/log/unbound` + newsyslog, keep-2 version GC |
| `pkg/ai.getunbound.discovery.plist` | System LaunchDaemon: local binary, `StartInterval` 43200, `RunAtLoad`, `LowPriorityIO`, `Nice` 10, zero network code fetch |
| `pkg/newsyslog-ai.getunbound.conf` | Log rotation for `/var/log/unbound/*.log` |

The rendered `onboard.sh` (from `../mdm/onboard.sh.tmpl`) is the Jamf
Script payload: the script never travels over the network, only the
hash-pinned pkg does.

## On-disk layout installed by the pkg

```
/opt/unbound/<version>/{unbound-hook/,unbound-discovery/,share/}
/opt/unbound/current -> /opt/unbound/<version>     (flipped by postinstall AFTER pre-warm)
/opt/unbound/etc/                                  (config; written by onboard, never by the pkg)
/Library/LaunchDaemons/ai.getunbound.discovery.plist
/var/log/unbound/                                  (+ /etc/newsyslog.d/ai.getunbound.conf)
```

Canonical binary paths (no `bin/` shim dir — aligned with the WEB-4786
binary): `/opt/unbound/current/unbound-hook/unbound-hook` and
`/opt/unbound/current/unbound-discovery/unbound-discovery`.

**Version contract:** `<binary> --version` output must contain the release
version as a whitespace-delimited token (e.g. `unbound-hook 1.2.3`) — the
CI install-test hard-fails a tag release whose binaries self-identify
otherwise (this is what keeps a placeholder build off the fleet). Real
specs must bake the release version at build time.

Receipts: `pkgutil --pkg-info ai.getunbound.runtime` → Jamf smart groups
report fleet coverage. Previous version dir is kept for rollback (keep-2 GC).

## Release stages are gated on credentials

The workflow runs end-to-end **unsigned** until secrets land; each stage
lights up independently:

| Stage | Enabled by |
|---|---|
| Mach-O signing | `APPLE_CERT_APPLICATION_P12` + `APPLE_APP_SIGNING_IDENTITY` (+ password) |
| pkg productsign | above + `APPLE_CERT_INSTALLER_P12` + `APPLE_INSTALLER_SIGNING_IDENTITY` + `APPLE_TEAM_ID` (installer signing without a Team ID is refused — the onboard.sh assert must never be empty in a signed release) |
| notarytool + staple + spctl | above + `APPLE_NOTARY_KEY_P8/_KEY_ID/_ISSUER_ID` |
| pinned discovery checkout (canonical spec) | `DISCOVERY_CHECKOUT_TOKEN` |
| S3 upload | `ARTIFACTS_AWS_ACCESS_KEY_ID` + `ARTIFACTS_AWS_SECRET_ACCESS_KEY` |

Artifacts publish to
`s3://unbound-release-artifacts/macos/<version>/` (public URL
`https://unbound-release-artifacts.s3.us-west-2.amazonaws.com/macos/<version>/…`,
baked into the rendered onboard.sh). The bucket **rejects overwrites**
(`put-object --if-none-match '*'`): a 412/AccessDenied on re-publish means
that version already shipped — bump the version and cut a new tag; never
retry or delete. Published artifacts are immutable so the sha256 baked
into the fleet's onboard.sh stays true forever.

A **tag** release refuses to run with partial signing credentials, missing
S3 credentials, or no discovery checkout token (no accidental unsigned
fleet artifacts, no baked URLs that 404, no placeholder binaries — the
install-test version assert backstops the last one); use
`workflow_dispatch` for unsigned dry-runs. All secrets
live ONLY in the GitHub `release` environment, with required reviewers set
to the SOC 2 production-approver list.

## Cutting a release

```
git tag runtime-v0.1.0 && git push origin runtime-v0.1.0
```

Dry-run without a tag: Actions → release-macos-runtime → Run workflow.
The `builder` input selects PyInstaller (default) or Nuitka (WEB-4804
bake-off); Nuitka artifacts carry a `-nuitka` suffix in the pkg/tar/Actions
artifact names so both builders' outputs can sit side by side for the EDR
rehearsal. Tag releases ignore the input and always build with PyInstaller.
