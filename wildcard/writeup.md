# Wallet Guard — Agent Games Wildcard Submission

**One-line pitch:** An API that tells you whether a token approval is safe *before*
you sign it — SAFE, CAUTION or DANGER, with the on-chain facts to back it up.

- **Live endpoint:** `<WORKER_URL>` (fill in after deploy)
- **Repo:** `<REPO_URL>` (fill in after publishing)
- **Track:** Wildcard
- **Stack:** One Cloudflare Worker file, plain JavaScript, no build step, no
  secrets, no API keys, no database. Only public read-only JSON-RPC endpoints.

## The problem

Almost every wallet drain starts the same way: a user signs an `approve()` they
did not really understand. Unlimited allowances to unknown contracts are the
standard ingredient of phishing and malicious dApps — and the wallet UI shows
little more than a hex address and a scary number. By the time the user notices,
the funds are gone.

Existing block explorers show the *current* allowance, but they do not answer
the question a user actually has at signing time: *"Is this approval risky?"*

## What Wallet Guard does

Send a `POST /guard` with the chain, token, spender, amount and (optionally)
your wallet address. Wallet Guard reads the chain and returns a verdict:

```json
{
  "verdict": "DANGER",
  "score": 100,
  "reasons": [
    "Unlimited approval requested (amount is \"unlimited\" or >= 2^255) — the spender could move your entire token balance at any time.",
    "Spender is an externally owned account (EOA), not a smart contract — legitimate approvals almost always target contracts."
  ],
  "facts": {
    "chain": "ethereum",
    "token": { "address": "0xA0b8...", "name": "USD Coin", "symbol": "USDC", "decimals": 6, "isContract": true },
    "spender": { "address": "0x0000...dEaD", "isContract": false, "knownAs": null },
    "owner": null,
    "amount": "unlimited",
    "amountRaw": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    "allowance": null,
    "balance": null
  },
  "disclaimer": "Wallet Guard is an automated risk estimate, not financial advice. Always verify the spender address and amount on a block explorer before signing."
}
```

### Checks performed (all read-only, on-chain)

1. **Token is a contract** — reads `eth_getCode`; a non-contract token is rejected
   with a clear `400`.
2. **Token metadata** — `name()`, `symbol()`, `decimals()` via `eth_call`, so the
   response is human-readable and the amount math uses the right decimals.
3. **Spender type** — `eth_getCode`: EOA spenders are flagged hard, because
   legitimate approvals almost always target contracts.
4. **Known-router allowlist** — a small, hand-curated list (Uniswap V2/V3 routers,
   Universal Router, PancakeSwap V2 Router). Known routers lower the risk; anything
   else is "unknown", not "trusted".
5. **Owner allowance + balance** (when `owner` is given) — reads
   `allowance(owner, spender)` and `balanceOf(owner)`. Flags an existing unlimited
   allowance and a requested amount larger than the balance.

### Scoring

| Signal | Points |
|---|---|
| Unlimited amount (>= 2^255) | +60 |
| Spender is an EOA | +50 |
| Spender already holds an unlimited allowance | +30 |
| Spender is an unknown contract | +25 |
| Amount exceeds the owner's balance | +25 |

`SAFE` 0–24, `CAUTION` 25–59, `DANGER` 60–100.

## How it works (architecture)

```
Client (wallet / dApp / curl)
  └─ POST /guard { chain, token, spender, amount, owner? }
       └─ Cloudflare Worker (single file, stateless)
            ├─ validate input (400 on bad input, nothing is guessed)
            ├─ eth_getCode(token) + eth_getCode(spender)
            ├─ eth_call name() / symbol() / decimals()
            ├─ eth_call allowance() + balanceOf()  (only if owner is given)
            └─ score + reasons → JSON
```

- **Chains:** Ethereum, BSC, Base (public RPCs, up to 3 fallback endpoints per
  chain, 8 s timeout each; `502` if all fail).
- **No secrets:** there is nothing to leak — no API keys, no private keys, no
  user data stored. CORS is open so any wallet or dApp front-end can call it.
- **Stateless and deterministic:** the same request against the same chain state
  returns the same facts. Anyone can reproduce the result by re-running the same
  `eth_call`s against a public RPC.

## Why this matters

- **Prevention beats recovery.** An approval check costs one HTTP call and zero
  gas; a drained wallet costs everything.
- **It fits where users already are.** A wallet can call `/guard` before showing
  the sign screen and translate `DANGER` into a plain-language warning.
- **It is small enough to trust.** One file, ~330 lines, no dependencies, no
  hidden network calls. The entire behavior is auditable in minutes.

## Verifiability

This submission does not (yet) wrap its answers in a zkVerify proof — that is
deliberate scope control for a one-file agent. What it *does* offer:

- Every fact in the response (`name`, `symbol`, `decimals`, `isContract`,
  `allowance`, `balance`) is a direct on-chain read. Anyone can verify each one
  independently against a public RPC or block explorer.
- The scoring rules are fixed, published in the README, and deterministic given
  the facts — there is no model, no hidden state, no randomness.

**Future work:** sign each response and anchor a Groth16 proof that the stated
facts match a recent state root, so a wallet can verify the assessment itself
without trusting the endpoint — exactly the kind of verifiable-agent pattern
Agent Games is about.

## Testing

Tested locally (15 Nov 2026, Node v24) against live public RPCs, no deploy
needed. 10/10 cases passed, including:

- USDC (Ethereum) + Uniswap V2 Router, amount `1000` → `SAFE` (score 0)
- USDC + EOA spender + `unlimited` → `DANGER` (score 100)
- USDC + unknown contract spender → `CAUTION` (score 25)
- BUSD (BSC) + PancakeSwap V2 Router → `SAFE` (score 0)
- Owner path: requested amount above the owner's balance → `CAUTION` (the
  balance check fires correctly)
- Invalid input (bad address, unknown chain, EOA as token) → clear `400`s

One environment note from testing: `eth.llamarpc.com` returned HTTP 525 from
the test VM, while `eth-mainnet.public.blastapi.io` worked — which is why the
worker lists Blast first for Ethereum and falls back automatically.

## Limitations (honest)

- Public RPCs can rate-limit; the worker falls back across endpoints and returns
  `502` when all fail.
- The known-router allowlist is tiny and hand-curated. Legitimate new protocols
  show up as `CAUTION` until added — that is the safe default.
- It judges the *approval shape*, not the *website*: a known router reached from
  a phishing front-end still looks `SAFE`. Pair it with domain checks in a real
  wallet integration.
- Not financial advice (the disclaimer ships in every response).

## Links

- Live endpoint: `<WORKER_URL>`
- Repo / source: `<REPO_URL>`
- Deploy: paste `wallet-guard-worker.js` into a Cloudflare Worker and hit Deploy —
  no build step, no environment variables.
