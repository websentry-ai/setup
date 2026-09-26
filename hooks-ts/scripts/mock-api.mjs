// Standalone runner for the same scripted mock the unit tests use (RESEARCH E4a manual smoke):
//
//   npm run mock-api -- --mode deny --port 8799
//   UNBOUND_GATEWAY_URL=http://127.0.0.1:8799 UNBOUND_PI_API_KEY=test pi
//
// Everything is logged to stderr, never stdout - pi's print/json modes own stdout.
// Run through the npm script (it supplies --experimental-strip-types for the .ts import).

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
];

function parseArgs(argv) {
  const parsed = { mode: process.env.MOCK_VERDICT ?? "deny", port: 8799, errorsMode: "ok" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--mode") parsed.mode = argv[++i];
    else if (arg === "--port") parsed.port = Number(argv[++i]);
    else if (arg === "--errors-mode") parsed.errorsMode = argv[++i];
    else {
      console.error(`unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  return parsed;
}

const { mode, port, errorsMode } = parseArgs(process.argv.slice(2));

if (!VALID_MODES.includes(mode)) {
  console.error(`invalid --mode ${mode}; valid modes: ${VALID_MODES.join(", ")}`);
  process.exit(2);
}
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  console.error(`invalid --port ${port}`);
  process.exit(2);
}

const mock = await startMockApi({ mode, errorsMode, port });

console.error(`[mock-api] listening on ${mock.url}`);
console.error(`[mock-api] pretool mode: ${mode}    errors mode: ${errorsMode}`);
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
