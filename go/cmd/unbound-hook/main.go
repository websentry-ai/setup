// Command unbound-hook is the Go rewrite of the PyInstaller hook binary.
// The python implementation under binary/ is the golden reference; this
// dispatcher mirrors binary/src/unbound_hook/main.py exactly.
//
// Subcommands:
//
//	hook <tool> [<event>]   stdin/stdout hook dispatch (fail-open, exit 0)
//	setup [...]             MDM onboarding (not implemented yet)
//	backfill [...]          historical transcript seeding (not implemented yet)
//	clear                   full deregistration (not implemented yet)
//	--version / version     print version (pkg postinstall pre-warm contract:
//	                        must exit fast without reading stdin)
package main

import (
	"fmt"
	"os"

	"github.com/websentry-ai/setup/go/internal/hooks"
)

// Version is baked at build time via -ldflags "-X main.Version=...".
var Version = "0.0.0-dev"

func usage() string {
	return fmt.Sprintf(`unbound-hook %s

Usage:
  unbound-hook hook <tool> [<event>]      tools: claude-code|cursor|copilot|codex
  unbound-hook setup --api-key <key> [--discovery-key <key>] [options]
  unbound-hook backfill (--all | --user <name>) [--dry-run] [options]
  unbound-hook clear
  unbound-hook --version
`, Version)
}

func run(args []string) int {
	if len(args) > 0 && (args[0] == "--version" || args[0] == "-V" || args[0] == "version") {
		// Pre-warm contract: print and exit, never touch stdin.
		fmt.Printf("unbound-hook %s\n", Version)
		return 0
	}
	if len(args) == 0 {
		fmt.Println(usage())
		return 2
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(usage())
		return 0
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "hook":
		tool, event := "", ""
		if len(rest) > 0 {
			tool = rest[0]
		}
		if len(rest) > 1 {
			event = rest[1]
		}
		return hooks.Dispatch(tool, event, os.Stdin, os.Stdout)
	case "setup", "backfill", "clear":
		// Admin commands are NOT fail-open: a silent no-op here would look
		// like a successful install/backfill/deregistration.
		fmt.Fprintf(os.Stderr, "unbound-hook %s: not implemented\n", cmd)
		return 1
	}

	fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
	fmt.Fprintln(os.Stderr, usage())
	return 2
}

func main() {
	os.Exit(run(os.Args[1:]))
}
