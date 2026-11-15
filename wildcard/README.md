# Wallet Guard

A tiny API that scores the risk of an ERC20 token approval **before you sign it**.
Built for the Agent Games by zkVerify — Wildcard track.

Most wallet-draining attacks start with one careless `approve()`: an unlimited
allowance to a malicious contract, or to an address that is not a contract at all.
Wallet Guard checks the token, the spender and (optionally) your current allowance
and balance — all read-only, on-chain — and answers `SAFE`, `CAUTION` or `DANGER`
with human-readable reasons.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Agent info + usage example |
| `GET` | `/health` | `{"ok": true}` |
| `POST` | `/guard` | Risk assessment |

### `POST /guard`

Request body (JSON):

```json
{
  "chain": "ethereum",
  "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "spender": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
  "amount": "1000",
  "owner": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
}
```

| Field | Required | Notes |
|---|---|---|
| `chain` | yes | `ethereum`, `bsc` or `base` |
| `token` | yes | ERC20 contract address (`0x` + 40 hex chars) |
| `spender` | yes | Address that would receive the allowance |
| `amount` | yes | Decimal string like `"100.5"`, or `"unlimited"` |
| `owner` | no | Your wallet address — enables allowance + balance checks |

Response (JSON):

```json
{
  "verdict": "SAFE",
  "score": 0,
  "reasons": [
    "Spender is a known contract: Uniswap V2 Router — a router commonly used by wallets and dApps.",
    "No risk signals detected: finite amount, known contract spender."
  ],
  "facts": {
    "chain": "ethereum",
    "token": { "address": "0xA0b8...", "name": "USD Coin", "symbol": "USDC", "decimals": 6, "isContract": true },
    "spender": { "address": "0x7a25...", "isContract": true, "knownAs": "Uniswap V2 Router" },
    "owner": null,
    "amount": "1000",
    "amountRaw": "1000000000",
    "allowance": null,
    "allowanceRaw": null,
    "balance": null,
    "balanceRaw": null
  },
  "disclaimer": "Wallet Guard is an automated risk estimate, not financial advice. Always verify the spender address and amount on a block explorer before signing."
}
```

`verdict` is `SAFE` (score 0–24), `CAUTION` (25–59) or `DANGER` (60–100).
`score` is 0–100, where 0 is safest.

### Scoring rules

| Signal | Points | Note |
|---|---|---|
| Amount is `unlimited` (or >= 2^255) | +60 | Spender could drain the whole balance |
| Spender is an EOA, not a contract | +50 | Legit approvals almost always target contracts |
| Spender already holds an unlimited allowance from this owner | +30 | Only checked when `owner` is given |
| Spender is an unknown contract | +25 | Not on the small known-router list |
| Requested amount exceeds the owner's balance | +25 | Only checked when `owner` is given |

### Errors

- `400` — bad input (unknown chain, malformed address, invalid amount, token is not a contract). The message says which field is wrong.
- `502` — all public RPC endpoints for that chain failed. Retry later.
- `404` / `405` — unknown path / wrong method.
- CORS is open (`Access-Control-Allow-Origin: *`), so a browser dApp can call it directly.

## Examples (curl)

Safe — USDC + Uniswap V2 Router:

```bash
curl -X POST https://<your-worker>/guard \
  -H "Content-Type: application/json" \
  -d '{"chain":"ethereum","token":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","spender":"0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D","amount":"1000"}'
# -> {"verdict":"SAFE","score":0,...}
```

Danger — unlimited approval to an EOA:

```bash
curl -X POST https://<your-worker>/guard \
  -H "Content-Type: application/json" \
  -d '{"chain":"ethereum","token":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","spender":"0x000000000000000000000000000000000000dEaD","amount":"unlimited"}'
# -> {"verdict":"DANGER","score":100,...}
```

## Deploy (Cloudflare Workers, ~2 minutes)

No build step, no secrets, no environment variables.

1. Go to the Cloudflare dashboard → **Workers & Pages** → **Create** → **Create Worker**.
2. Delete the template code and paste the entire contents of `wallet-guard-worker.js`.
3. Click **Deploy**. Your URL is `https://<name>.<subdomain>.workers.dev`.
4. Test: `curl https://<your-worker>/health` → `{"ok":true}`.

Alternative with Wrangler:

```bash
npx wrangler deploy wallet-guard-worker.js --name wallet-guard
```

## Known-router allowlist (deliberately small)

| Address | Name |
|---|---|
| `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D` | Uniswap V2 Router |
| `0xE592427A0AEce92De3Edee1F63E0157F8Df20fE6e` | Uniswap V3 SwapRouter |
| `0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45` | Uniswap V3 SwapRouter02 |
| `0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD` | Uniswap Universal Router |
| `0x10ED43C718714eb63d5aA57B78B54704E256024E` | PancakeSwap V2 Router |

Any spender not on this list is reported as an *unknown contract* (+25, `CAUTION`
at minimum). That is intentional: the allowlist is a convenience for famous
routers, not a trust seal. Unknown does not mean malicious — it means "verify it
yourself on a block explorer".

## Limitations (honest)

- **Public RPCs can rate-limit.** The worker tries up to three public endpoints
  per chain with an 8-second timeout each and returns `502` if all fail.
  During local testing (15 Nov 2026) `eth.llamarpc.com` returned HTTP 525 from
  the test VM, while `eth-mainnet.public.blastapi.io` worked — that is why Blast
  is listed first for Ethereum.
- **The allowlist is tiny and hand-curated.** It covers the most-used DEX routers
  only. A legitimate new protocol will show up as `CAUTION` until added.
- **It checks the approval, not the dApp.** A known router called from a phishing
  front-end still looks `SAFE` — the tool answers "is this approval shape risky",
  not "is this website honest".
- **No zkVerify proof integration (yet).** The assessment is deterministic and
  reproducible from public chain state — anyone can re-run the same `eth_call`s
  and get the same facts — but the response itself is not (yet) wrapped in a
  Groth16 proof. See `writeup.md` for the verifiability notes and future work.
- **Not financial advice.** See the disclaimer in every response.

## Local tests

Tested 15 Nov 2026 with Node v24 against live public RPCs (no deploy).
Harness: `/tmp/test-wallet-guard.mjs` (scratch, not part of the submission).

| Case | Result |
|---|---|
| `GET /health` | `{"ok": true}` |
| `GET /` | info JSON |
| USDC (Ethereum) + Uniswap V2 Router, `1000`, no owner | `SAFE`, score 0 |
| USDC + EOA spender + `unlimited` | `DANGER`, score 100 |
| USDC + unknown contract spender, `100` | `CAUTION`, score 25 |
| BUSD (BSC) + PancakeSwap V2 Router, `100` | `SAFE`, score 0 |
| USDC + V2 Router + owner (amount > balance) | `CAUTION`, score 25 — balance check works |
| Bad spender address / unknown chain / EOA as token | `400` with a clear message |

10/10 passed.
