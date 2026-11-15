# Agent Games by zkVerify — @pamankolak's entries

My entries for [Agent Games](https://agentgames.zkverify.io) (zkVerify / Horizen Labs, 21 Oct – 21 Nov 2026). Two agents, one repo.

## 1. Proof Gatekeeper agent — `gatekeeper-agent.js`

HTTPS agent for the **Proof Gatekeeper** track. It verifies signed payment tasks, decides APPROVE/REJECT with a deterministic policy (7 trap checks: VK substitution, proof reuse, threshold, expiry, recipient, amount), and generates a **Groth16 proof** of its decision with snarkjs against the official gatekeeper circuit — all inside the 60s deadline.

- Endpoint: `POST /agent` (HMAC-signed), `GET /health`
- Circuit artifacts: `circuits/` (`gatekeeper.wasm`, `gatekeeper_final.zkey`, `verification_key.json` — official, from `/api/circuit-info`)
- Tests: `node test-agent.js` — 13/13 pass (valid + 6 trap cases + idempotency + auth failures; every proof locally verified)
- Deploy: Vercel serverless, entry `api/agent.js`, `vercel.json` (`maxDuration: 10`)
- Env: `AGENT_GAMES_HMAC_SECRET` (required, from the Agent Games dashboard), `SEEN_STORE_PATH` (set to `/tmp/gatekeeper-seen.json` on Vercel — filesystem is read-only elsewhere), `KURIER_API_KEY` (optional — without it, proofs are still generated and returned; only the on-chain Kurier submission is skipped)
- Details: `docs/gatekeeper-proof-setup.md`, `docs/gatekeeper-test-results.md`

## 2. Wallet Guard — `wildcard/wallet-guard-worker.js`

Cloudflare Worker for the **Wildcard** track. Screens a token approval **before** you sign it: checks the token contract, the spender (contract vs EOA, known router allowlist), and the owner's allowance/balance, then returns a verdict `SAFE` / `CAUTION` / `DANGER` + score 0–100 + reasons.

- `POST /guard` `{chain, token, spender, amount, owner?}` — public RPCs only, no secrets
- Tests: 10/10 pass against live public RPCs (see `wildcard/README.md`)
- Details + submission write-up: `wildcard/README.md`, `wildcard/writeup.md`

## Creator Track

Thread: "Don't trust the agent, verify it — my agent earns its keep on-chain" — posted from [@pamankolak](https://x.com/pamankolak) and submitted to the Agent Games dashboard (Creator Track, PENDING review).
