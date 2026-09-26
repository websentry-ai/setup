// Standalone runner for the same scripted mock the unit tests use (RESEARCH E4a manual smoke):
//
//   npm run mock-api -- --mode deny --port 8799
//   UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test pi
//
// Everything is logged to stderr, never stdout - pi's print/json modes own stdout.
// Run through the npm script (it supplies --experimental-strip-types for the .ts import).
//
// NOTE: the mock models the server's Path-2 entry gate, so a pretool request carrying neither a
// command nor a metadata.file_path is answered `allow` with `_entry_gate: no_evaluable_input`
// whatever --mode says. That is faithful to the real API; see mockApi.ts's header.

import { startMockApi } from "../packages/core/test/helpers/mockApi.ts";

const VALID_MODES = [
  "allow",
  "deny",
  "denyNoReason",
  "ask",
  "approval",
  "failBlock",
  "500",
  "malformed",
  "hang",
  "attributed",
  "errors",
  "toolsList",
  "toolsEmpty",
  "toolsOmitted",
  "401",
];

const VALID_ERRORS_MODES = ["ok", "500", "hang"];
const VALID_TURNLOG_MODES = ["ok", "401", "hang"];

const USAGE = `usage: npm run mock-api -- [options]

  --mode <mode>           POST /v1/hooks/pretool behaviour (default: deny, env MOCK_VERDICT)
                          ${VALID_MODES.join(", ")}
  --errors-mode <mode>    POST /v1/hooks/errors behaviour (default: ok)
                          ${VALID_ERRORS_MODES.join(", ")}
  --turnlog-mode <mode>   POST /v1/hooks/pi turn-log behaviour (default: ok)
                          ${VALID_TURNLOG_MODES.join(", ")}
  --port <n>              listen port (default: 8799)
  --help                  print this and exit 0

  toolsList returns tools_to_check: ["read","write"]; toolsEmpty returns []; toolsOmitted omits
  the key entirely; 401 rejects every pretool request (the errors route keeps --errors-mode).`;

function parseArgs(argv) {
  const parsed = {
    mode: process.env.MOCK_VERDICT ?? "deny",
    port: 8799,
    errorsMode: "ok",
    turnLogMode: "ok",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mode") parsed.mode = argv[++i];
    else if (arg === "--port") parsed.port = Number(argv[++i]);
    else if (arg === "--errors-mode") parsed.errorsMode = argv[++i];
    else if (arg === "--turnlog-mode") parsed.turnLogMode = argv[++i];
    else if (arg === "--help" || arg === "-h") {
      console.error(USAGE);
      process.exit(0);
    } else {
      console.error(`unknown argument: ${arg}`);
      console.error(USAGE);
      process.exit(2);
    }
  }
  return parsed;
}

const { mode, port, errorsMode, turnLogMode } = parseArgs(process.argv.slice(2));

if (!VALID_MODES.includes(mode)) {
  console.error(`invalid --mode ${mode}; valid modes: ${VALID_MODES.join(", ")}`);
  process.exit(2);
}
if (!VALID_ERRORS_MODES.includes(errorsMode)) {
  console.error(`invalid --errors-mode ${errorsMode}; valid modes: ${VALID_ERRORS_MODES.join(", ")}`);
  process.exit(2);
}
if (!VALID_TURNLOG_MODES.includes(turnLogMode)) {
  console.error(
    `invalid --turnlog-mode ${turnLogMode}; valid modes: ${VALID_TURNLOG_MODES.join(", ")}`,
  );
  process.exit(2);
}
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`invalid --port ${port}`);
  process.exit(2);
}

const mock = await startMockApi({ mode, errorsMode, turnLogMode, port });

console.error(`[mock-api] listening on ${mock.url}`);
console.error(
  `[mock-api] pretool mode: ${mode}    errors mode: ${errorsMode}    turn-log mode: ${turnLogMode}`,
);
console.error(`[mock-api] UNBOUND_GATEWAY_URL=${mock.url} UNBOUND_PI_API_KEY=test pi`);

let logged = 0;
const tail = setInterval(() => {
  while (logged < mock.requests.length) {
    const req = mock.requests[logged];
    logged += 1;
    console.error(`[mock-api] ${req.method} ${req.path} -> ${mode}`);
  }
}, 200);

const shutdown = async () => {
  clearInterval(tail);
  console.error(`[mock-api] closing after ${mock.requests.length} request(s)`);
  await mock.close();
  process.exit(0);
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
