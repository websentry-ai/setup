package locks

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func backdate(t *testing.T, path string, age time.Duration) {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireExclCreatesLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	if !AcquireExcl(path, time.Minute) {
		t.Fatal("expected acquisition of missing lock")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("lock file not created: %v", err)
	}
}

func TestAcquireExclFreshLockLoses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	if !AcquireExcl(path, time.Minute) {
		t.Fatal("setup acquire failed")
	}
	if AcquireExcl(path, time.Minute) {
		t.Error("fresh lock must not be re-acquired")
	}
}

func TestAcquireExclStealsStaleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	if !AcquireExcl(path, time.Minute) {
		t.Fatal("setup acquire failed")
	}
	backdate(t, path, 2*time.Minute)
	if !AcquireExcl(path, time.Minute) {
		t.Error("stale lock must be stolen")
	}
}

func TestAcquireExclMissingParentDirFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "x.lock")
	if AcquireExcl(path, time.Minute) {
		t.Error("expected failure when parent dir is missing")
	}
}

func TestClaimFirstWins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.lock")
	ok, err := Claim(path, 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("Claim = %v, %v", ok, err)
	}
	ok, err = Claim(path, 10*time.Second)
	if err != nil || ok {
		t.Errorf("fresh marker must block: Claim = %v, %v", ok, err)
	}
}

func TestClaimStealsStaleMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.lock")
	if ok, _ := Claim(path, 10*time.Second); !ok {
		t.Fatal("setup claim failed")
	}
	backdate(t, path, time.Minute)
	ok, err := Claim(path, 10*time.Second)
	if err != nil || !ok {
		t.Errorf("stale marker must be stolen: Claim = %v, %v", ok, err)
	}
}

func TestClaimMissingParentDirPropagatesError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "d.lock")
	ok, err := Claim(path, 10*time.Second)
	if ok || err == nil {
		t.Errorf("Claim = %v, %v; want false + error (python propagates non-EEXIST)", ok, err)
	}
}

func TestIsFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.lock")
	if IsFresh(path, time.Minute) {
		t.Error("missing file must not be fresh")
	}
	if err := Touch(path); err != nil {
		t.Fatal(err)
	}
	if !IsFresh(path, time.Minute) {
		t.Error("just-touched file must be fresh")
	}
	backdate(t, path, 2*time.Minute)
	if IsFresh(path, time.Minute) {
		t.Error("backdated file must be stale")
	}
}

func TestReleaseIgnoresMissing(t *testing.T) {
	Release(filepath.Join(t.TempDir(), "never-existed.lock")) // must not panic
}

func TestTouchBumpsMtime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t")
	if err := Touch(path); err != nil {
		t.Fatal(err)
	}
	backdate(t, path, time.Hour)
	if err := Touch(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(fi.ModTime()) > time.Minute {
		t.Errorf("Touch did not bump mtime: %v", fi.ModTime())
	}
}
