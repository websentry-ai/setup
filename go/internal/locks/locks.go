// Package locks ports the python hooks' mtime-TTL lock-file patterns.
// Exact TTLs stay with the callers; this package is only the mechanism.
//
//   - AcquireExcl mirrors _acquire_self_update_lock
//     (claude-code/hooks/unbound.py lines 1238-1248): a fresh lock loses,
//     a stale one is unlinked, then an O_CREAT|O_EXCL create decides the
//     winner; every failure mode returns false (fail-closed: skip the work).
//   - Claim mirrors the discovery dispatch marker (lines 1513-1530):
//     O_CREAT|O_EXCL first; on "already exists" check staleness and steal
//     (unlink + re-create) only if older than the TTL. Errors other than
//     "exists" on the first create propagate, like the python code letting
//     non-FileExistsError OSErrors reach the outer handler.
//   - IsFresh mirrors the discovery.lock busy check (lines 1502-1508):
//     a stat failure is treated as stale (python sets age = TTL + 1).
//   - Release mirrors unlink(missing_ok=True) under try/except.
//   - Touch mirrors Path.touch(): create the file or bump its mtime
//     (self-update state stamp, error-report rate-limit marker).
package locks

import (
	"errors"
	"io/fs"
	"os"
	"time"
)

// AcquireExcl takes the lock at path unless a fresh one (younger than ttl)
// exists. Returns true only when this caller created the lock file.
func AcquireExcl(path string, ttl time.Duration) bool {
	if fi, err := os.Stat(path); err == nil {
		if time.Since(fi.ModTime()) < ttl {
			return false
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// Claim atomically creates the dispatch marker at path. A fresh existing
// marker yields (false, nil); a stale one is stolen. A first-create failure
// that is not fs.ErrExist is returned as an error (python propagates it).
func Claim(path string, ttl time.Duration) (bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		f.Close()
		return true, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return false, err
	}
	age := ttl + time.Second // stat failure counts as stale (python: TTL + 1)
	if fi, statErr := os.Stat(path); statErr == nil {
		age = time.Since(fi.ModTime())
	}
	if age < ttl {
		return false, nil
	}
	if err := os.Remove(path); err != nil {
		return false, nil
	}
	f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return false, nil
	}
	f.Close()
	return true, nil
}

// IsFresh reports whether path exists and is younger than ttl. Unstattable
// files count as stale. The python self-update throttle (_self_update_due)
// is exactly !IsFresh(statePath, interval).
func IsFresh(path string, ttl time.Duration) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < ttl
}

// Release removes the lock file, ignoring all errors.
func Release(path string) {
	_ = os.Remove(path)
}

// Touch creates path if missing and bumps its mtime to now.
func Touch(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o666)
	if err != nil {
		return err
	}
	f.Close()
	now := time.Now()
	return os.Chtimes(path, now, now)
}
