/**
 * Which shell runs a Pi shell-tool call. Pi's tools name it: `bash` runs bash (Git Bash on Windows) unless the user set
 * `shellPath` in Pi's agent-dir `settings.json`, and `powershell` runs PowerShell 7 when it is on PATH, else Windows
 * PowerShell. Mirrors the Python hooks' shell detection; never throws, and says nothing when it can't tell.
 */
import { existsSync, lstatSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";

import { resolvePiAgentDir } from "./cache.ts";
import { MAX_CONFIG_BYTES } from "./constants.ts";
import { readSmallRegularFile } from "./safeRead.ts";

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

/** A settings file the safe reader won't follow (a link), so Pi's shell can't be known from here. */
const UNREADABLE = Symbol("unreadable");

function isLink(path: string): boolean {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function piShellPath(): unknown {
  try {
    const dir = resolvePiAgentDir(process.env, homedir());
    if (dir === undefined) return undefined;
    const file = join(dir, "settings.json");
    const raw = readSmallRegularFile(file, MAX_CONFIG_BYTES);
    if (raw === undefined) return isLink(file) ? UNREADABLE : undefined;
    const settings: unknown = JSON.parse(raw.replace(/^\uFEFF/, ""));
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
    // A shellPath that names no known shell is still the shell Pi runs, so it names nothing rather than bash.
    const custom = tool === "bash" ? piShellPath() : undefined;
    // Pi follows a linked settings file this reader won't open, so its shell is unknown rather than bash.
    if (custom === UNREADABLE) {
      shellCache.set(tool, {});
      return {};
    }
    const shell =
      tool === "powershell"
        ? process.platform === "win32" && !onPath("pwsh")
          ? "powershell"
          : "pwsh"
        : typeof custom === "string" && custom !== ""
          ? shellName(custom)
          : "bash";
    info = shell === undefined ? {} : { shell, shell_source: "tool" };
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
