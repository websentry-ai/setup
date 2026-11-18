// The shell a Pi shell-tool call runs in, on the pretool body and the turn log. The end-to-end run of the real
// bundle (setup's tests/test_transfer_e2e.py) covers bash on this machine; these cover the rest.

import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

import { buildPretoolPayload } from "../src/payload.ts";
import { detectShell, resetShellCache } from "../src/shell.ts";
import { buildTurnLogBody } from "../src/turnLog.ts";
import type { PretoolPayloadInput } from "../src/types.ts";

function withEnv(env: Record<string, string>, platform: NodeJS.Platform, fn: () => void): void {
  const saved = { HOME: process.env.HOME, PATH: process.env.PATH, PI_CODING_AGENT_DIR: process.env.PI_CODING_AGENT_DIR };
  const savedPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  delete process.env.PI_CODING_AGENT_DIR;
  Object.assign(process.env, env);
  Object.defineProperty(process, "platform", { value: platform });
  resetShellCache();
  try {
    fn();
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    if (savedPlatform) Object.defineProperty(process, "platform", savedPlatform);
    resetShellCache();
  }
}

function home(): string {
  return mkdtempSync(join(tmpdir(), "pi-shell-"));
}

const input: PretoolPayloadInput = {
  toolName: "bash",
  command: "npm test",
  toolInput: { command: "npm test" },
  cwd: "/tmp/project",
  sessionId: "sess-shell",
  model: undefined,
  clientEntrypoint: "pi/0.87.1",
};

test("bash runs bash unless Pi's shellPath setting picks another shell", () => {
  const dir = home();
  const bash = () => detectShell("bash");
  withEnv({ HOME: dir }, "linux", () => assert.deepEqual(bash(), { shell: "bash", shell_source: "tool" }));
  mkdirSync(join(dir, ".pi", "agent"), { recursive: true });
  writeFileSync(join(dir, ".pi", "agent", "settings.json"), JSON.stringify({ shellPath: "/usr/bin/zsh" }));
  withEnv({ HOME: dir }, "linux", () => assert.deepEqual(bash(), { shell: "zsh", shell_source: "tool" }));
  writeFileSync(join(dir, ".pi", "agent", "settings.json"), JSON.stringify({ shellPath: "/usr/bin/nu" }));
  withEnv({ HOME: dir }, "linux", () => assert.deepEqual(bash(), {}));
});

test("Pi's settings are read from PI_CODING_AGENT_DIR when it is set", () => {
  const agent = home();
  writeFileSync(join(agent, "settings.json"), JSON.stringify({ shellPath: "/bin/fish" }));
  withEnv({ HOME: home(), PI_CODING_AGENT_DIR: agent }, "linux", () =>
    assert.deepEqual(detectShell("bash"), { shell: "fish", shell_source: "tool" }));
});

test("a linked Pi settings file names no shell, as Pi follows the link and this reader won't", () => {
  const dir = home();
  const real = join(home(), "settings.json");
  writeFileSync(real, JSON.stringify({ shellPath: "/usr/bin/zsh" }));
  mkdirSync(join(dir, ".pi", "agent"), { recursive: true });
  symlinkSync(real, join(dir, ".pi", "agent", "settings.json"));
  withEnv({ HOME: dir }, "linux", () => assert.deepEqual(detectShell("bash"), {}));
});

test("powershell runs PowerShell 7 when it is on PATH and Windows PowerShell when not", () => {
  const bin = home();
  withEnv({ HOME: home(), PATH: bin }, "win32", () =>
    assert.deepEqual(detectShell("powershell"), { shell: "powershell", shell_source: "tool" }));
  writeFileSync(join(bin, "pwsh.exe"), "");
  withEnv({ HOME: home(), PATH: bin }, "win32", () =>
    assert.deepEqual(detectShell("powershell"), { shell: "pwsh", shell_source: "tool" }));
});

test("only a shell tool is named, and an MCP call's body never carries a shell", () => {
  assert.deepEqual(detectShell("read"), {});
  const shell = { shell: "bash", shell_source: "tool" as const };
  const bash = buildPretoolPayload({ ...input, shell }).pre_tool_use_data;
  assert.deepEqual([bash.shell, bash.shell_source], ["bash", "tool"]);
  const mcp = buildPretoolPayload({ ...input, shell, mcp: { server: "linear", tool: "create_issue", args: {} } });
  assert.equal("shell" in mcp.pre_tool_use_data, false);
  assert.equal("shell" in buildPretoolPayload(input).pre_tool_use_data, false);
});

test("the turn log names the shell on shell calls only", () => {
  withEnv({ HOME: home() }, "linux", () => {
    const call = (tool_name: string, tool_use_id: string) =>
      ({ tool_name, tool_use_id, decision: "allow", ts: 1, tool_input: {} });
    const body = buildTurnLogBody(
      { prompt: "p", session_id: "s", started_at: 1, tool_calls: [call("bash", "a"), call("read", "b")], results: [] },
      { cwd: "/tmp/project", completedAtMs: 2 },
    );
    const uses = body.messages.flatMap((m) => m.tool_use ?? []);
    assert.deepEqual(
      uses.map((u) => [u.tool_name, u.shell, u.shell_source]),
      [["bash", "bash", "tool"], ["read", undefined, undefined]],
    );
  });
});
