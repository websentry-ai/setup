/**
 * Which shell runs a Pi shell-tool call. Pi's tools name it: `bash` runs bash (Git Bash on Windows) unless the user set
 * `shellPath` in `~/.pi/agent/settings.json`, and `powershell` runs PowerShell 7 when it is on PATH, else Windows
 * PowerShell. Mirrors the Python hooks' shell detection; never throws, and says nothing when it can't tell.
 */
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";

const SHELL_NAMES = new Set(["bash", "zsh", "sh", "fish", "dash", "ksh", "powershell", "pwsh", "cmd"]);

export interface ShellInfo {
  shell?: string;
  shell_source?: "tool";
}

const shellCache = new Map<string, ShellInfo>();

/** The shell a path or program name runs (`/bin/zsh`, `pwsh.exe`), or undefined for anything else. */
function shellName(program: unknown): string | undefined {
  if (typeof program !== "string" || program.trim() === "") return undefined;
  let name = (program.trim().replace(/^"|"$/g, "").split(/[\\/]/).pop() ?? "").toLowerCase();
  if (name.endsWith(".exe")) name = name.slice(0, -4);
  return SHELL_NAMES.has(name) ? name : undefined;
}

function onPath(program: string): boolean {
  const suffixes = process.platform === "win32" ? [".exe", ""] : [""];
  return (process.env.PATH ?? "")
    .split(delimiter)
    .some((dir) => dir !== "" && suffixes.some((suffix) => existsSync(join(dir, program + suffix))));
}

function piShellPath(): unknown {
  try {
    const settings: unknown = JSON.parse(readFileSync(join(homedir(), ".pi", "agent", "settings.json"), "utf8"));
    if (settings === null || typeof settings !== "object") return undefined;
    return (settings as Record<string, unknown>).shellPath;
  } catch {
    return undefined;
  }
}

/** `{ shell, shell_source }` for a `bash` or `powershell` call, `{}` for any other tool or when it can't tell. */
export function detectShell(toolName: unknown): ShellInfo {
  if (typeof toolName !== "string") return {};
  const tool = toolName.toLowerCase();
  if (tool !== "bash" && tool !== "powershell") return {};
  const cached = shellCache.get(tool);
  if (cached !== undefined) return { ...cached };
  let info: ShellInfo = {};
  try {
    const shell =
      tool === "powershell"
        ? process.platform === "win32" && !onPath("pwsh")
          ? "powershell"
          : "pwsh"
        : (shellName(piShellPath()) ?? "bash");
    info = { shell, shell_source: "tool" };
  } catch {
    info = {};
  }
  shellCache.set(tool, info);
  return { ...info };
}

/** Forget cached answers; for tests that change PATH or settings between calls. */
export function resetShellCache(): void {
  shellCache.clear();
}
