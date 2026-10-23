// Package httpc shells out to curl for all HTTP, exactly like the python
// hook modules — never net/http. This is a deliberate house rule: corporate
// TLS interception (Zscaler etc.) trusts the system curl's CA handling
// where a static Go TLS stack would fail closed.
//
// Each helper mirrors a python curl invocation byte-for-byte in argv order:
//
//   - PostJSON mirrors send_to_hook_api / send_to_api / poll_approval_status
//     (claude-code/hooks/unbound.py lines 523-531, 564-572, 1083-1091):
//     curl -fsSL -X POST -H "Authorization: Bearer <key>"
//     -H "Content-Type: application/json" --data-binary @- <url>,
//     body on stdin, subprocess timeout per caller.
//   - Get mirrors _hook_discovery_enabled_for_org (lines 1383-1389):
//     curl -fsSL -H "Authorization: Bearer <key>" --max-time <n> <url>.
//   - Fetch mirrors _download_latest_hook (lines 1253-1255):
//     curl -fsSL --max-time <n> <url>.
//   - Download mirrors the install.sh refresh (lines 1561-1563):
//     curl -fsSL -o <dest> <url>.
//   - PostJSONDetached mirrors report_error_to_gateway's fire-and-forget
//     Popen (lines 103-113): start curl, write the body to its stdin,
//     close, never wait.
//
// Fail-open contract: any failure here (curl missing, non-zero exit,
// timeout) is an error/exit-code the callers treat as allow/skip — the
// hook process must never block the editor on transport problems.
package httpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"
)

// Result is the captured outcome of a curl run, mirroring python
// subprocess.run(capture_output=True): callers check ExitCode == 0 and
// Stdout themselves (e.g. `result.returncode == 0 and result.stdout`).
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// run executes curl with args, mirroring subprocess.run(..., timeout=N):
// a non-zero curl exit is a Result (not an error); spawn failures and the
// timeout kill are errors (python's except branch / TimeoutExpired).
func run(args []string, stdin []byte, timeout time.Duration) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", args...)
	// After the deadline kill, don't wait forever for pipe EOF (curl spawns
	// no children, so in practice the pipes close with the process).
	cmd.WaitDelay = time.Second
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return Result{}, fmt.Errorf("httpc: curl timed out after %s", timeout)
	}
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return Result{}, err
	}
	return res, nil
}

// PostJSON POSTs body as application/json with a Bearer api key. The body
// travels via stdin (--data-binary @-) so it never appears in argv.
func PostJSON(url, apiKey string, body []byte, timeout time.Duration) (Result, error) {
	args := []string{"-fsSL", "-X", "POST",
		"-H", "Authorization: Bearer " + apiKey,
		"-H", "Content-Type: application/json",
		"--data-binary", "@-", url}
	if body == nil {
		body = []byte{}
	}
	return run(args, body, timeout)
}

// Get performs an authenticated GET with curl's own --max-time cap plus the
// outer subprocess timeout (python passes both, e.g. --max-time 5 / timeout=8).
func Get(url, apiKey string, maxTimeSecs int, timeout time.Duration) (Result, error) {
	args := []string{"-fsSL",
		"-H", "Authorization: Bearer " + apiKey,
		"--max-time", strconv.Itoa(maxTimeSecs),
		url}
	return run(args, nil, timeout)
}

// Fetch GETs a URL with no auth header (self-update payload download).
func Fetch(url string, maxTimeSecs int, timeout time.Duration) (Result, error) {
	args := []string{"-fsSL", "--max-time", strconv.Itoa(maxTimeSecs), url}
	return run(args, nil, timeout)
}

// Download GETs a URL straight to a file (-o dest), no auth header.
func Download(url, dest string, timeout time.Duration) (Result, error) {
	args := []string{"-fsSL", "-o", dest, url}
	return run(args, nil, timeout)
}

// PostJSONDetached fires a POST and returns without waiting, like python's
// Popen with DEVNULL stdio: the curl child outlives the hook process. The
// body is written to curl's stdin synchronously (small payloads only) and
// a background goroutine reaps the child if we are still alive when it
// exits. Errors are returned for callers that log; none ever block.
func PostJSONDetached(url, apiKey string, body []byte) error {
	cmd := exec.Command("curl", "-fsSL", "-X", "POST",
		"-H", "Authorization: Bearer "+apiKey,
		"-H", "Content-Type: application/json",
		"--data-binary", "@-", url)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		stdin.Close()
		return err
	}
	_, werr := stdin.Write(body)
	cerr := stdin.Close()
	go func() { _ = cmd.Wait() }()
	if werr != nil {
		return werr
	}
	return cerr
}
