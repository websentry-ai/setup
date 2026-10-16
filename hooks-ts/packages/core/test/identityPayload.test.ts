// `account_identity` on the wire: present exactly when an identity is known, absent otherwise, on
// every body the Claude Code hook sends it on (pretool, prompt check, turn log) plus the heartbeat.

import assert from "node:assert/strict";
import test from "node:test";

import type { AccountIdentity } from "../src/accountIdentity.ts";
import { buildHeartbeatPayload } from "../src/heartbeat.ts";
import { buildPretoolPayload, buildPromptPayload } from "../src/payload.ts";
import { buildTurnLogBody } from "../src/turnLog.ts";
import { TEST_PROFILE } from "./helpers/testProfile.ts";

const IDENTITY: AccountIdentity = {
  auth_mode: "subscription",
  user_email: "dev@example.com",
  email_domain: "example.com",
  org_id: "org-1",
  plan: "claude_max",
  device_serial: "C02ABC",
};

const pretool = (accountIdentity?: AccountIdentity) =>
  buildPretoolPayload({
    toolName: "bash",
    command: "ls",
    toolInput: { command: "ls" },
    cwd: "/tmp",
    sessionId: "s",
    model: undefined,
    clientEntrypoint: "pi/0.87.1",
    ...(accountIdentity === undefined ? {} : { accountIdentity }),
  }, TEST_PROFILE);

const prompt = (accountIdentity?: AccountIdentity) =>
  buildPromptPayload({
    prompt: "hi",
    cwd: "/tmp",
    sessionId: "s",
    model: undefined,
    clientEntrypoint: "pi/0.87.1",
    hasUI: true,
    ...(accountIdentity === undefined ? {} : { accountIdentity }),
  }, TEST_PROFILE);

const heartbeat = (accountIdentity?: AccountIdentity) =>
  buildHeartbeatPayload({
    cwd: "/tmp",
    sessionId: "s",
    model: undefined,
    clientEntrypoint: "pi/0.87.1",
    hasUI: true,
    agentVersion: "0.87.1",
    ...(accountIdentity === undefined ? {} : { accountIdentity }),
  }, TEST_PROFILE);

const turnLog = (accountIdentity?: AccountIdentity) =>
  buildTurnLogBody(
    { prompt: "hi", tool_calls: [], results: [], session_id: "s" },
    { cwd: "/tmp", completedAtMs: 0, ...(accountIdentity === undefined ? {} : { accountIdentity }) },
  );

const builders = { pretool, prompt, heartbeat, turnLog } as const;

for (const [name, build] of Object.entries(builders)) {
  test(`${name}: account_identity rides the body when known`, () => {
    const body = build(IDENTITY) as unknown as Record<string, unknown>;
    assert.deepEqual(body.account_identity, IDENTITY);
  });

  test(`${name}: no identity means no key at all`, () => {
    for (const absent of [undefined, {}]) {
      const body = build(absent as AccountIdentity | undefined) as unknown as Record<string, unknown>;
      assert.equal(Object.hasOwn(body, "account_identity"), false);
    }
  });

  test(`${name}: only string fields of the wire vocabulary are forwarded`, () => {
    const dirty = { ...IDENTITY, plan: 5, access: "sk-ant-oat01-secret", extra: "x" } as unknown as AccountIdentity;
    const body = build(dirty) as unknown as Record<string, unknown>;
    const sent = body.account_identity as Record<string, unknown>;
    assert.equal(sent.plan, undefined);
    assert.equal(sent.access, undefined);
    assert.equal(sent.extra, undefined);
    assert.equal(JSON.stringify(body).includes("sk-ant-oat01-secret"), false);
  });
}

test("the identity is copied, so a later mutation of the source cannot change a built body", () => {
  const source: AccountIdentity = { auth_mode: "api_key" };
  const body = pretool(source);
  source.auth_mode = "subscription";
  assert.deepEqual(body.account_identity, { auth_mode: "api_key" });
});
