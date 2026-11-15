/**
 * Local test harness for gatekeeper-agent.js.
 *
 * Spawns the agent on a test port with a throwaway HMAC secret, replays
 * signed envelopes (1 valid + 6 trap cases + idempotency + auth failures),
 * checks decision + reason_code, and locally verifies every returned
 * Groth16 proof with snarkjs against circuits/verification_key.json.
 *
 * Run:  node test-agent.js
 * Exit code 0 = all checks passed.
 */
"use strict";

const { spawn } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const PORT = 18787;
const SECRET = "test-secret-do-not-use-in-production-0123456789";
const BASE = `http://127.0.0.1:${PORT}`;
const VK = JSON.parse(
  fs.readFileSync(path.join(__dirname, "circuits", "verification_key.json"), "utf8"),
);

const BASE_INPUT = {
  registered_vk: "0x7d3a11111111111111111111111111111111f291",
  proof_vk: "0x7d3a11111111111111111111111111111111f291",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 8430000,
  current_block: 8420000,
  recipient: "0xDe4200000000000000000000000000000000009f01",
  condition_recipient: "0xDe4200000000000000000000000000000000009f01",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xa8c100000000000000000000000000000000000000000000000000000000002c",
};

function sign(rawBody) {
  return crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");
}

async function post(pathname, obj, { badSig = false, rawOverride = null } = {}) {
  const raw = rawOverride !== null ? rawOverride : JSON.stringify(obj);
  const sig = badSig ? "00".repeat(32) : sign(raw);
  const t0 = Date.now();
  const res = await fetch(BASE + pathname, {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sig },
    body: raw,
  });
  const text = await res.text();
  return { status: res.status, ms: Date.now() - t0, body: text, respSig: res.headers.get("x-agent-games-signature") };
}

function taskEnvelope(taskId, input) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 55_000).toISOString(),
    input,
  };
}

function verifyRespSig(body, sig) {
  if (!sig) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(body).digest();
  let cand;
  if (/^[0-9a-fA-F]{64}$/.test(sig)) cand = Buffer.from(sig, "hex");
  else return false;
  return cand.length === expected.length && crypto.timingSafeEqual(cand, expected);
}

async function waitHealth(proc) {
  for (let i = 0; i < 40; i++) {
    try {
      const r = await fetch(BASE + "/health");
      if (r.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
    if (proc.exitCode !== null) throw new Error("agent exited early");
  }
  throw new Error("agent did not become healthy");
}

async function main() {
  // Clean seen-store for a deterministic run.
  const seenPath = path.join(__dirname, "data", "seen.test.json");
  try { fs.unlinkSync(seenPath); } catch { /* ignore */ }

  const proc = spawn("node", ["gatekeeper-agent.js"], {
    cwd: __dirname,
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      SEEN_STORE_PATH: seenPath,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  proc.stdout.on("data", (d) => { serverLog += d; });
  proc.stderr.on("data", (d) => { serverLog += d; });

  const results = [];
  const check = (name, ok, detail) => {
    results.push({ name, ok, detail });
    console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  };

  try {
    await waitHealth(proc);

    // 0. Preflight
    {
      const env = { type: "agent-games.preflight.v1", agent_id: "agt_test", issued_at: new Date().toISOString(), nonce: "abc123" };
      const r = await post("/agent", env);
      const j = JSON.parse(r.body);
      check("preflight -> {ok:true, protocolVersion:v1} + valid response signature",
        r.status === 200 && j.ok === true && j.protocolVersion === "v1" && verifyRespSig(r.body, r.respSig),
        `status=${r.status} ${r.ms}ms`);
    }

    // 1. Valid -> APPROVE + proof verifies
    let validBody = null;
    {
      const r = await post("/agent", taskEnvelope("gk_test_valid_1", BASE_INPUT));
      const j = JSON.parse(r.body);
      let proofOk = false;
      if (j.proof && j.public_signals) {
        proofOk = await snarkjs.groth16.verify(VK, j.public_signals, j.proof);
      }
      const ps = j.public_signals || [];
      const signalsOk = ps.length === 13 && ps[11] === "1"; // decision=1 approve
      check("valid -> APPROVE/VALID_CONDITION + proof verifies locally",
        r.status === 200 && j.decision === "APPROVE" && j.reason_code === "VALID_CONDITION" &&
        proofOk && signalsOk && verifyRespSig(r.body, r.respSig),
        `status=${r.status} proofOk=${proofOk} signals=${ps.length} ${r.ms}ms`);
      validBody = r.body;
    }

    // 2. Idempotent redelivery of the same task -> identical cached body
    {
      const r = await post("/agent", taskEnvelope("gk_test_valid_1", BASE_INPUT));
      check("redelivery same task_id -> identical cached response",
        r.status === 200 && r.body === validBody, `status=${r.status}`);
    }

    const trapCases = [
      ["VK_SUBSTITUTION", { ...BASE_INPUT, proof_vk: "0xa4c1000000000000000000000000000000000000b8ff", proof_tx: "0xa8c10000000000000000000000000000000000000000000000000000000000a1" }],
      ["THRESHOLD_MISMATCH", { ...BASE_INPUT, public_balance: "999", proof_tx: "0xa8c10000000000000000000000000000000000000000000000000000000000a2" }],
      ["EXPIRED_CONDITION", { ...BASE_INPUT, current_block: 8430000, proof_tx: "0xa8c10000000000000000000000000000000000000000000000000000000000a3" }],
      ["RECIPIENT_MISMATCH", { ...BASE_INPUT, recipient: "0xDe4200000000000000000000000000000000001234", proof_tx: "0xa8c10000000000000000000000000000000000000000000000000000000000a4" }],
      ["AMOUNT_OVERFLOW", { ...BASE_INPUT, amount: "1001", proof_tx: "0xa8c10000000000000000000000000000000000000000000000000000000000a5" }],
    ];
    for (const [reason, input] of trapCases) {
      const r = await post("/agent", taskEnvelope(`gk_test_${reason.toLowerCase()}`, input));
      const j = JSON.parse(r.body);
      let proofOk = false;
      if (j.proof && j.public_signals) {
        proofOk = await snarkjs.groth16.verify(VK, j.public_signals, j.proof);
      }
      const ps = j.public_signals || [];
      check(`${reason} -> REJECT/${reason} + proof verifies (decision=0)`,
        r.status === 200 && j.decision === "REJECT" && j.reason_code === reason &&
        proofOk && ps.length === 13 && ps[11] === "0" && verifyRespSig(r.body, r.respSig),
        `status=${r.status} proofOk=${proofOk} ${r.ms}ms`);
    }

    // 3. PROOF_REUSED: same proof_tx as the valid case, new task_id -> no proof
    {
      const r = await post("/agent", taskEnvelope("gk_test_reused_1", BASE_INPUT));
      const j = JSON.parse(r.body);
      check("PROOF_REUSED -> REJECT/PROOF_REUSED with NO proof",
        r.status === 200 && j.decision === "REJECT" && j.reason_code === "PROOF_REUSED" &&
        !j.proof && !j.public_signals && j.proof_tx === BASE_INPUT.proof_tx,
        `status=${r.status} ${r.ms}ms`);
    }

    // 4. Bad signature -> 401
    {
      const r = await post("/agent", taskEnvelope("gk_test_badsig", BASE_INPUT), { badSig: true });
      check("bad HMAC signature -> HTTP 401", r.status === 401, `status=${r.status}`);
    }

    // 5. Malformed JSON with valid HMAC -> 400 REJECT/INVALID_TASK
    {
      const r = await post("/agent", null, { rawOverride: "{not json" });
      let j = null;
      try { j = JSON.parse(r.body); } catch { /* ignore */ }
      check("malformed JSON (valid HMAC) -> REJECT/INVALID_TASK",
        r.status === 400 && j && j.decision === "REJECT" && j.reason_code === "INVALID_TASK",
        `status=${r.status}`);
    }

    // 6. Wrong type -> 400 REJECT/INVALID_TASK
    {
      const r = await post("/agent", { type: "agent-games.unknown.v1" });
      const j = JSON.parse(r.body);
      check("unknown envelope type -> REJECT/INVALID_TASK",
        r.status === 400 && j.decision === "REJECT" && j.reason_code === "INVALID_TASK",
        `status=${r.status}`);
    }

    // 7. Boundary values: balance == minimum, amount == max_transfer, current == expiry-1 -> APPROVE
    {
      const input = { ...BASE_INPUT, public_balance: "1000", amount: "1000", current_block: 8429999, proof_tx: "0xa8c1000000000000000000000000000000000000000000000000000000000099" };
      const r = await post("/agent", taskEnvelope("gk_test_boundary", input));
      const j = JSON.parse(r.body);
      let proofOk = false;
      if (j.proof && j.public_signals) proofOk = await snarkjs.groth16.verify(VK, j.public_signals, j.proof);
      check("boundary (balance==min, amount==max, block==expiry-1) -> APPROVE + proof verifies",
        r.status === 200 && j.decision === "APPROVE" && j.reason_code === "VALID_CONDITION" && proofOk,
        `status=${r.status} proofOk=${proofOk} ${r.ms}ms`);
    }
  } finally {
    proc.kill("SIGTERM");
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  if (failed.length) {
    console.log("---- server log (tail) ----");
    console.log(serverLog.split("\n").slice(-30).join("\n"));
    process.exit(1);
  }
}

main().catch((e) => {
  console.error("HARNESS ERROR:", e);
  process.exit(2);
});
