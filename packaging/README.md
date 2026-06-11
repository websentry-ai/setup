# macOS runtime packaging (Non-Python MDM Rollout)

Everything the `release-macos-runtime` workflow needs to turn a
`runtime-v*` tag into a signed, notarized, stapled pkg + tar.gz on S3 and a
GitHub Release. Tickets: WEB-4789 (pipeline), WEB-4791 (onboard.sh
template), WEB-4792 (pkg payload).

## Layout

| Path | What |
|---|---|
| `versions.env` | Pinned python.org universal2 CPython (URL + sha256), pkg identifier, install prefix, daemon label |
| `requirements-build.txt` | Hash-pinned PyInstaller toolchain (`pip install --require-hashes`) |
| `discovery.lock` | Pinned `coding-discovery-tool` SHA checked out into `./discovery-src` at build time |
| `specs/*.spec` | Committed PyInstaller specs — **placeholders** until Streams A (`unbound-hook`) and B (`unbound-discovery`) drop the real ones; bundle names, onedir COLLECT layout, and `target_arch='universal2'` are the pipeline contract |
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
/opt/unbound/<version>/{unbound-hook/,unbound-discovery/,bin/,share/}
/opt/unbound/current -> /opt/unbound/<version>     (flipped by postinstall AFTER pre-warm)
/opt/unbound/etc/                                  (config; written by onboard, never by the pkg)
/Library/LaunchDaemons/ai.getunbound.discovery.plist
/var/log/unbound/                                  (+ /etc/newsyslog.d/ai.getunbound.conf)
```

Receipts: `pkgutil --pkg-info ai.getunbound.runtime` → Jamf smart groups
report fleet coverage. Previous version dir is kept for rollback (keep-2 GC).

## Release stages are gated on credentials

The workflow runs end-to-end **unsigned** until secrets land; each stage
lights up independently:

| Stage | Enabled by |
|---|---|
| Mach-O signing | `APPLE_CERT_APPLICATION_P12` + `APPLE_APP_SIGNING_IDENTITY` (+ password) |
| pkg productsign | above + `APPLE_CERT_INSTALLER_P12` + `APPLE_INSTALLER_SIGNING_IDENTITY` |
| notarytool + staple + spctl | above + `APPLE_NOTARY_KEY_P8/_KEY_ID/_ISSUER_ID` |
| pinned discovery checkout | `DISCOVERY_CHECKOUT_TOKEN` |
| S3 upload | vars `RUNTIME_S3_BUCKET` + `AWS_RELEASE_ROLE_ARN` (OIDC; bucket comes from the infra track) |

A **tag** release refuses to run with partial signing credentials (no
accidental unsigned fleet artifacts); use `workflow_dispatch` for unsigned
dry-runs. All secrets live ONLY in the GitHub `release` environment, with
required reviewers set to the SOC 2 production-approver list.

## Cutting a release

```
git tag runtime-v0.1.0 && git push origin runtime-v0.1.0
```

Dry-run without a tag: Actions → release-macos-runtime → Run workflow.
