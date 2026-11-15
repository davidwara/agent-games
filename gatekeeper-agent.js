/**
 * Proof Gatekeeper agent — zkVerify Agent Games (own implementation).
 *
 * Plain Node.js HTTP service (no framework). The platform POSTs signed task
 * envelopes to POST /agent; this service verifies the HMAC, decides
 * APPROVE/REJECT with deterministic policy, generates a Groth16 proof
 * locally with snarkjs against the official gatekeeper circuit, optionally
 * submits the proof to zkVerify mainnet via Kurier, and returns a signed
 * response — all inside the 60 s hard deadline.
 *
 * Protocol source of truth: https://agentgames.zkverify.io/build
 * (Agent interface, Circuit artifacts, Security checklist) and
 * https://agentgames.zkverify.io/events/proof-gatekeeper (trap taxonomy).
 * Circuit inputs were confirmed by proving against the official
 * gatekeeper.wasm / gatekeeper_final.zkey (see proof-setup.md).
 *
 * Secrets (NEVER hardcode, NEVER commit):
 *   AGENT_GAMES_HMAC_SECRET (preferred) | GATEKEEPER_HMAC_SECRET (alias)
 *   — 32-byte secret from the dashboard ("Rotate Secret").
 *   Fallback file: ~/.agent-games/gatekeeper-hmac.txt (single line).
 *   KURIER_API_KEY (optional) — Kurier mainnet API key; without it the
 *   agent still answers with proof + public_signals, only the on-chain
 *   submission step is skipped.
 *
 * Run:  AGENT_GAMES_HMAC_SECRET=... node gatekeeper-agent.js
 * Env:  PORT (default 8787), KURIER_API_KEY, KURIER_API_URL,
 *       GATEKEEPER_VK_HASH, CIRCUITS_DIR, SEEN_STORE_PATH,
 *       KURIER_POLL_BUDGET_MS (default 15000), TASK_SOFT_DEADLINE_MS (45000).
 */

"use strict";

const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";
const SIG_HEADER = "x-agent-games-signature";

const GATEKEEPER_VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const KURIER_API_URL =
  process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const PORT = Number(process.env.PORT || 8787);
const TASK_SOFT_DEADLINE_MS = Number(process.env.TASK_SOFT_DEADLINE_MS || 45000);
const KURIER_POLL_BUDGET_MS = Number(process.env.KURIER_POLL_BUDGET_MS || 15000);
const KURIER_POLL_INTERVAL_MS = Number(process.env.KURIER_POLL_INTERVAL_MS || 3000);
const CIRCUITS_DIR =
  process.env.CIRCUITS_DIR || path.join(__dirname, "circuits");
const SEEN_STORE_PATH =
  process.env.SEEN_STORE_PATH || path.join(__dirname, "data", "seen.json");

function loadHmacSecret() {
  if (process.env.AGENT_GAMES_HMAC_SECRET) return process.env.AGENT_GAMES_HMAC_SECRET;
  if (process.env.GATEKEEPER_HMAC_SECRET) return process.env.GATEKEEPER_HMAC_SECRET;
  const file = path.join(
    process.env.HOME || process.env.USERPROFILE || "~",
    ".agent-games",
    "gatekeeper-hmac.txt",
  );
  try {
    const v = fs.readFileSync(file, "utf8").trim();
    if (v) return v;
  } catch {
    /* no file — handled below */
  }
  return "";
}

const HMAC_SECRET = loadHmacSecret();
const KURIER_API_KEY = process.env.KURIER_API_KEY || null;

// ---------------------------------------------------------------------------
// HMAC helpers (HMAC-SHA256, lowercase hex; inbound accepts hex/base64,
// optional "sha256=" prefix; constant-time compare)
// ---------------------------------------------------------------------------

function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function decodeMacCandidate(headerValue) {
  let v = String(headerValue || "").trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch {
    /* fall through */
  }
  return null;
}

function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const candidate = decodeMacCandidate(headerValue);
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return (
    candidate.length === expected.length &&
    crypto.timingSafeEqual(candidate, expected)
  );
}

/** Per-task private salt: HMAC(secret, "gatekeeper-salt:"+task_id) mod p. */
function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

// ---------------------------------------------------------------------------
// Field conversion (envelope value -> BN128 field element, decimal string)
// ---------------------------------------------------------------------------

function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      // Free-form identifier (e.g. task_id "gk_8d31_x"): SHA-256 into the field.
      n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
    }
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

// ---------------------------------------------------------------------------
// Deterministic policy (trap taxonomy, in documented check order)
// ---------------------------------------------------------------------------

function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null || publicBalance === null || amount === null ||
    maxTransfer === null || expiryBlock === null || currentBlock === null
  ) return null;
  for (const f of ["registered_vk", "proof_vk", "recipient", "condition_recipient", "proof_tx"]) {
    if (typeof input[f] !== "string" || !input[f]) return null;
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum, publicBalance, expiryBlock, currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount, maxTransfer,
    proofTx: input.proof_tx,
  };
}

const normHex = (v) => String(v || "").trim().toLowerCase();

function evaluate(parsed, isProofTxSeen) {
  if (normHex(parsed.proofVk) !== normHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    // Documented special case: a reused-proof task has no proof to submit.
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normHex(parsed.recipient) !== normHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

function buildCircuitInputs(taskId, parsed, decision, salt) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

// ---------------------------------------------------------------------------
// Seen-store (proof_tx set + idempotent response cache, JSON-file backed)
// ---------------------------------------------------------------------------

class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seen = new Set();
    this.responses = new Map();
    this.load();
  }
  load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.filePath, "utf8"));
      if (Array.isArray(raw.seen)) raw.seen.forEach((x) => this.seen.add(String(x)));
      if (raw.responses && typeof raw.responses === "object") {
        for (const [k, v] of Object.entries(raw.responses)) this.responses.set(k, v);
      }
    } catch {
      /* first run — empty store */
    }
  }
  save() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = this.filePath + ".tmp";
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          seen: [...this.seen],
          responses: Object.fromEntries(this.responses),
        }),
      );
      fs.renameSync(tmp, this.filePath);
    } catch (e) {
      console.error("[store] save failed:", e.message);
    }
  }
  hasProofTx(tx) { return this.seen.has(String(tx)); }
  getResponse(taskId) { return this.responses.get(taskId) || null; }
  record(taskId, proofTx, responseBody) {
    this.seen.add(String(proofTx));
    if (taskId) this.responses.set(taskId, responseBody);
    this.save();
  }
}

const store = new SeenStore(SEEN_STORE_PATH);

// ---------------------------------------------------------------------------
// Kurier (zkVerify mainnet) — never throws; returns null on any failure.
// txHash exists from "Submitted" onward (~4 s); we do NOT wait for Finalized.
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function kurierSubmit(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const res = await fetch(`${KURIER_API_URL}/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: GATEKEEPER_VK_HASH },
      }),
    });
    if (!res.ok) {
      console.error(`[kurier] submit-proof HTTP ${res.status}`);
      return null;
    }
    const job = await res.json();
    if (!job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }
    let status = "Submitted";
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(Math.min(KURIER_POLL_INTERVAL_MS, Math.max(0, deadline - Date.now())));
      let s;
      try {
        const r = await fetch(`${KURIER_API_URL}/job-status/${KURIER_API_KEY}/${job.jobId}`);
        if (!r.ok) continue;
        s = await r.json();
      } catch {
        continue;
      }
      status = s.status || status;
      const txHash = s.txHash || (s.transactionInfo && s.transactionInfo.txHash);
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") return { jobId: job.jobId, status, txHash, finalized: false };
      if (txHash) return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
    }
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (e) {
    console.error("[kurier] submission error:", e.message);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Request handling
// ---------------------------------------------------------------------------

function parseTimestamp(v) {
  if (typeof v === "number" && Number.isFinite(v)) return v < 1e12 ? v * 1000 : v;
  if (typeof v === "string") {
    const s = v.trim();
    if (/^[0-9]+$/.test(s)) {
      const n = Number(s);
      if (Number.isFinite(n)) return n < 1e12 ? n * 1000 : n;
    }
    const t = Date.parse(s);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

function signedResult(status, obj) {
  const body = JSON.stringify(obj);
  return { status, body, signature: signBody(HMAC_SECRET, body) };
}

async function handleTask(task, startedAt) {
  // Idempotent redelivery: same task_id -> cached response, never re-evaluate
  // (a redelivery must not be mistaken for proof reuse).
  if (task.task_id) {
    const cached = store.getResponse(task.task_id);
    if (cached) return { status: 200, body: cached, signature: signBody(HMAC_SECRET, cached) };
  }

  const now = Date.now();
  const deadlineMs = parseTimestamp(task.deadline_at);
  const issuedMs = parseTimestamp(task.issued_at);
  if (deadlineMs !== null && now > deadlineMs) {
    return signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  if (issuedMs !== null && issuedMs > now + 5 * 60_000) {
    return signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  const parsed = parseInput(task.input);
  if (!parsed || !task.task_id) {
    return signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  const evaluation = evaluate(parsed, (tx) => store.hasProofTx(tx));
  const response = { decision: evaluation.decision, reason_code: evaluation.reason_code };

  if (evaluation.provable) {
    const salt = deriveSalt(HMAC_SECRET, task.task_id);
    const circuitInputs = buildCircuitInputs(task.task_id, parsed, evaluation.decision, salt);
    try {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInputs,
        path.join(CIRCUITS_DIR, "gatekeeper.wasm"),
        path.join(CIRCUITS_DIR, "gatekeeper_final.zkey"),
      );
      response.proof = proof;
      response.public_signals = publicSignals;

      // Kurier submission, bounded so the answer stays well inside 60 s.
      // Never blocks on finalization: return as soon as a txHash exists.
      const remaining = TASK_SOFT_DEADLINE_MS - (Date.now() - startedAt);
      const budget = Math.min(KURIER_POLL_BUDGET_MS, Math.max(0, remaining));
      const kurier = await kurierSubmit(proof, publicSignals, budget);
      response.proof_tx = kurier && kurier.txHash ? kurier.txHash : parsed.proofTx;
    } catch (e) {
      // Proving failed: fail closed. A claimed APPROVE without a valid proof
      // is the worst outcome — downgrade to REJECT with no proof.
      console.error("[agent] proof generation failed:", e.message);
      return signedResult(200, {
        decision: "REJECT",
        reason_code: evaluation.decision === "APPROVE" ? "INVALID_TASK" : evaluation.reason_code,
        proof_tx: parsed.proofTx,
      });
    }
  } else {
    // PROOF_REUSED: documented as having no proof to submit; echo the reference.
    response.proof_tx = parsed.proofTx;
  }

  const result = signedResult(200, response);
  // Record only after a successful evaluation, so a task never flags itself.
  store.record(task.task_id, parsed.proofTx, result.body);
  return result;
}

async function handlePost(rawBody, signatureHeader) {
  const startedAt = Date.now();

  if (!HMAC_SECRET) {
    return {
      status: 500,
      body: JSON.stringify({ error: "server_misconfigured", detail: "HMAC secret not set" }),
      signature: null,
    };
  }

  // 1. Authenticate the raw body BEFORE parsing.
  if (!verifyBodySignature(HMAC_SECRET, rawBody, signatureHeader)) {
    return { status: 401, body: JSON.stringify({ error: "invalid_signature" }), signature: null };
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return signedResult(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  // 2. Preflight handshake.
  if (envelope.type === PREFLIGHT_TYPE) {
    return signedResult(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
  }
  if (envelope.type !== TASK_TYPE) {
    return signedResult(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  // 3. Task — any internal error fails closed to REJECT.
  try {
    return await handleTask(envelope, startedAt);
  } catch (e) {
    console.error("[agent] task handling error:", e.message);
    return signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

function logLine(req, status, ms, extra) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.url} -> ${status} ${ms}ms${extra ? " " + extra : ""}`);
}

function handleRequest(req, res) {
  const startedAt = Date.now();
  const send = (result) => {
    res.writeHead(result.status, {
      "content-type": "application/json",
      ...(result.signature ? { [SIG_HEADER]: result.signature } : {}),
    });
    res.end(result.body);
    logLine(req, result.status, Date.now() - startedAt);
  };

  if (req.method === "GET" && (req.url === "/health" || req.url === "/")) {
    const body = JSON.stringify({
      ok: true,
      protocolVersion: PROTOCOL_VERSION,
      agent: "proof-gatekeeper",
      kurier: KURIER_API_KEY ? "configured" : "not-configured",
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
    logLine(req, 200, Date.now() - startedAt);
    return;
  }

  if (req.method === "POST" && (req.url === "/agent" || req.url === "/")) {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const rawBody = Buffer.concat(chunks);
      // Soft internal deadline guard: if we are already past it, fail closed.
      if (Date.now() - startedAt > TASK_SOFT_DEADLINE_MS) {
        return send(signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" }));
      }
      try {
        const result = await handlePost(rawBody, req.headers[SIG_HEADER]);
        const elapsed = Date.now() - startedAt;
        // Log a compact task line (never log bodies or secrets).
        try {
          const parsed = JSON.parse(result.body);
          if (parsed.decision) {
            console.log(
              `[task] ${parsed.decision} ${parsed.reason_code} ` +
              `proof=${parsed.proof ? "yes" : "no"} ` +
              `proof_tx=${(parsed.proof_tx || "").slice(0, 18)} ${elapsed}ms`,
            );
          }
        } catch { /* ignore */ }
        send(result);
      } catch (e) {
        console.error("[agent] unexpected error:", e.message);
        send(signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" }));
      }
    });
    req.on("error", () => send(signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" })));
    return;
  }

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: "not_found" }));
  logLine(req, 404, Date.now() - startedAt);
}

const server = http.createServer(handleRequest);

if (require.main === module) {
  server.listen(PORT, "0.0.0.0", () => {
  console.log(`[agent] Proof Gatekeeper listening on :${PORT} (POST /agent, GET /health)`);
  console.log(`[agent] HMAC secret: ${HMAC_SECRET ? "set" : "NOT SET — server will answer 500"}`);
  console.log(`[agent] Kurier: ${KURIER_API_KEY ? "configured" : "not configured (proofs still generated locally)"}`);
  console.log(`[agent] Circuits: ${CIRCUITS_DIR}`);
  console.log(`[agent] Seen store: ${SEEN_STORE_PATH}`);
  });
}

module.exports = handleRequest;
