/**
 * Wallet Guard — Agent Games by zkVerify (Wildcard track)
 * ======================================================
 * A tiny API that scores the risk of a token approval BEFORE the user signs it.
 *
 * One file, plain JavaScript, no build step, no secrets, no API keys.
 * Only public read-only JSON-RPC endpoints are used.
 *
 * Deploy: paste this file into a Cloudflare Worker (module format) and hit Deploy.
 * No environment variables, no bindings, no KV, no Durable Objects.
 *
 * Endpoints:
 *   GET  /        -> agent info + usage
 *   GET  /health  -> {"ok": true}
 *   POST /guard   -> risk assessment (see README.md for the request format)
 */

const RPCS = {
  // Ordered by reliability observed 2026-11-15. First working endpoint wins.
  // eth.llamarpc.com returned HTTP 525 from our test VM, so Blast public is first.
  ethereum: [
    'https://eth-mainnet.public.blastapi.io',
    'https://eth.llamarpc.com',
    'https://cloudflare-eth.com',
  ],
  bsc: [
    'https://bsc-dataseed.binance.org',
    'https://bsc-dataseed1.defibit.io',
    'https://bsc-dataseed1.ninicoin.io',
  ],
  base: [
    'https://mainnet.base.org',
    'https://base.llamarpc.com',
  ],
};

// Small, manually curated allowlist of well-known router contracts.
// Deliberately tiny: anything not on this list is "unknown", not "trusted".
// Addresses are CREATE2 deployments, identical on every EVM chain that has them.
const KNOWN_SPENDERS = {
  '0x7a250d5630b4cf539739df2c5dacb4c659f2488d': 'Uniswap V2 Router',
  '0xe592427a0aece92de3edee1f63e0157f8df20fe6e': 'Uniswap V3 SwapRouter',
  '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45': 'Uniswap V3 SwapRouter02',
  '0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad': 'Uniswap Universal Router',
  '0x10ed43c718714eb63d5aa57b78b54704e256024e': 'PancakeSwap V2 Router',
};

const MAX_UINT256 = 2n ** 256n - 1n;
const UNLIMITED_THRESHOLD = 2n ** 255n; // anything >= 2^255 is effectively unlimited
const RPC_TIMEOUT_MS = 8000;
const DISCLAIMER =
  'Wallet Guard is an automated risk estimate, not financial advice. ' +
  'Always verify the spender address and amount on a block explorer before signing.';

// ---------- small helpers ----------

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}

function isAddress(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
}

function hexToUtf8(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return new TextDecoder().decode(bytes).replace(/\0+$/, '');
}

// Decode an ABI-encoded string return value (offset + length + data).
function decodeAbiString(hex) {
  if (!hex || typeof hex !== 'string' || hex === '0x' || hex.length < 130) return null;
  try {
    const body = hex.slice(2);
    const len = parseInt(body.slice(64, 128), 16);
    if (!Number.isFinite(len) || len < 0 || len > 1000) return null;
    return hexToUtf8(body.slice(128, 128 + len * 2));
  } catch {
    return null;
  }
}

function decodeUint256(hex) {
  if (!hex || typeof hex !== 'string' || hex === '0x') return null;
  try {
    return BigInt(hex);
  } catch {
    return null;
  }
}

// "100.5" + 6 decimals -> 100500000n
function parseAmountToRaw(amountStr, decimals) {
  const [intPart = '0', fracPart = ''] = amountStr.split('.');
  const frac = (fracPart + '0'.repeat(decimals)).slice(0, decimals);
  return BigInt(intPart || '0') * 10n ** BigInt(decimals) + BigInt(frac || '0');
}

function formatUnits(raw, decimals) {
  const s = raw.toString().padStart(decimals + 1, '0');
  const int = s.slice(0, -decimals) || '0';
  const frac = s.slice(-decimals).replace(/0+$/, '');
  return frac ? `${int}.${frac}` : int;
}

function padAddress(addr) {
  return '0'.repeat(24) + addr.slice(2).toLowerCase();
}

// ---------- JSON-RPC (read-only, public endpoints, with fallback) ----------

async function rpcCall(chain, method, params) {
  const endpoints = RPCS[chain];
  let lastError = null;
  for (const url of endpoints) {
    try {
      const signal =
        typeof AbortSignal.timeout === 'function'
          ? AbortSignal.timeout(RPC_TIMEOUT_MS)
          : undefined;
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error.message || 'RPC error');
      return data.result;
    } catch (e) {
      lastError = e; // try the next endpoint
    }
  }
  throw new Error(`All RPC endpoints failed for ${chain}: ${lastError?.message || lastError}`);
}

async function ethCall(chain, to, data) {
  return rpcCall(chain, 'eth_call', [{ to, data }, 'latest']);
}

async function getCode(chain, address) {
  return rpcCall(chain, 'eth_getCode', [address, 'latest']);
}

// ---------- /guard ----------

const SELECTORS = {
  name: '0x06fdde03',
  symbol: '0x95d89b41',
  decimals: '0x313ce567',
  allowance: '0xdd62ed3e',
  balanceOf: '0x70a08231',
};

async function handleGuard(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid JSON body.' }, 400);
  }

  const { chain, token, spender, amount, owner } = body || {};

  // ---- validation (clear 400s, nothing is guessed) ----
  if (!chain || !RPCS[chain]) {
    return json({ error: 'Invalid chain. Use one of: ethereum, bsc, base.' }, 400);
  }
  if (!isAddress(token)) {
    return json({ error: 'Invalid token: expected a 0x address (40 hex chars).' }, 400);
  }
  if (!isAddress(spender)) {
    return json({ error: 'Invalid spender: expected a 0x address (40 hex chars).' }, 400);
  }
  if (owner !== undefined && owner !== null && owner !== '' && !isAddress(owner)) {
    return json({ error: 'Invalid owner: expected a 0x address (40 hex chars).' }, 400);
  }
  if (typeof amount !== 'string' || amount.trim() === '') {
    return json({ error: 'Invalid amount: provide a decimal string like "100.5" or "unlimited".' }, 400);
  }
  const amountLower = amount.trim().toLowerCase();
  const isUnlimitedStr = amountLower === 'unlimited';
  if (!isUnlimitedStr && !/^\d+(\.\d+)?$/.test(amount.trim())) {
    return json({ error: 'Invalid amount: provide a decimal string like "100.5" or "unlimited".' }, 400);
  }

  // ---- on-chain facts (parallel, read-only) ----
  let tokenCode, spenderCode, nameHex, symbolHex, decimalsHex;
  try {
    [tokenCode, spenderCode, nameHex, symbolHex, decimalsHex] = await Promise.all([
      getCode(chain, token),
      getCode(chain, spender),
      ethCall(chain, token, SELECTORS.name).catch(() => null),
      ethCall(chain, token, SELECTORS.symbol).catch(() => null),
      ethCall(chain, token, SELECTORS.decimals).catch(() => null),
    ]);
  } catch (e) {
    return json({ error: 'Upstream RPC unavailable, please retry.', details: String(e.message || e) }, 502);
  }

  const tokenIsContract = tokenCode && tokenCode !== '0x' && tokenCode !== '0x0';
  if (!tokenIsContract) {
    return json({ error: `Token ${token} is not a contract on ${chain}.` }, 400);
  }
  const spenderIsContract = spenderCode && spenderCode !== '0x' && spenderCode !== '0x0';
  const spenderKey = spender.toLowerCase();
  const knownAs = KNOWN_SPENDERS[spenderKey] || null;

  const name = decodeAbiString(nameHex);
  const symbol = decodeAbiString(symbolHex);
  const decimalsRaw = decodeUint256(decimalsHex);
  const decimals = decimalsRaw === null ? 18 : Number(decimalsRaw);
  const decimalsFallback = decimalsRaw === null;

  // ---- amount in raw units ----
  const amountRaw = isUnlimitedStr ? MAX_UINT256 : parseAmountToRaw(amount.trim(), decimals);
  const isUnlimited = amountRaw >= UNLIMITED_THRESHOLD;

  // ---- optional owner facts: current allowance + balance ----
  let allowanceRaw = null;
  let balanceRaw = null;
  const hasOwner = isAddress(owner);
  if (hasOwner) {
    const [allowHex, balHex] = await Promise.all([
      ethCall(chain, token, SELECTORS.allowance + padAddress(owner) + padAddress(spender)).catch(() => null),
      ethCall(chain, token, SELECTORS.balanceOf + padAddress(owner)).catch(() => null),
    ]);
    allowanceRaw = decodeUint256(allowHex);
    balanceRaw = decodeUint256(balHex);
  }

  // ---- risk scoring (0 = safe, 100 = worst) ----
  let score = 0;
  const reasons = [];

  if (isUnlimited) {
    score += 60;
    reasons.push(
      'Unlimited approval requested (amount is "unlimited" or >= 2^255) — the spender could move your entire token balance at any time.'
    );
  }
  if (!spenderIsContract) {
    score += 50;
    reasons.push(
      'Spender is an externally owned account (EOA), not a smart contract — legitimate approvals almost always target contracts.'
    );
  } else if (knownAs) {
    reasons.push(`Spender is a known contract: ${knownAs} — a router commonly used by wallets and dApps.`);
  } else {
    score += 25;
    reasons.push(
      'Spender is a contract that is not on the small known-router list — verify the address on a block explorer before signing.'
    );
  }
  if (hasOwner && allowanceRaw !== null && allowanceRaw >= UNLIMITED_THRESHOLD) {
    score += 30;
    reasons.push('This spender ALREADY holds an unlimited allowance from this owner.');
  } else if (hasOwner && allowanceRaw !== null && allowanceRaw > 0n) {
    reasons.push(
      `An allowance of ${formatUnits(allowanceRaw, decimals)} ${symbol || 'tokens'} already exists for this spender.`
    );
  }
  if (hasOwner && balanceRaw !== null && !isUnlimited && amountRaw > balanceRaw) {
    score += 25;
    reasons.push(
      `Requested amount (${amount.trim()} ${symbol || 'tokens'}) exceeds the owner's token balance (${formatUnits(balanceRaw, decimals)} ${symbol || 'tokens'}).`
    );
  }
  if (decimalsFallback) {
    reasons.push('Could not read token decimals on-chain; assumed 18 for the amount math.');
  }
  if (score === 0) {
    reasons.push('No risk signals detected: finite amount, known contract spender.');
  }

  if (score > 100) score = 100;
  const verdict = score >= 60 ? 'DANGER' : score >= 25 ? 'CAUTION' : 'SAFE';

  return json({
    verdict,
    score,
    reasons,
    facts: {
      chain,
      token: { address: token, name, symbol, decimals, isContract: true },
      spender: { address: spender, isContract: spenderIsContract, knownAs },
      owner: hasOwner ? owner : null,
      amount: isUnlimitedStr ? 'unlimited' : amount.trim(),
      amountRaw: amountRaw.toString(),
      allowance: allowanceRaw === null ? null : formatUnits(allowanceRaw, decimals),
      allowanceRaw: allowanceRaw === null ? null : allowanceRaw.toString(),
      balance: balanceRaw === null ? null : formatUnits(balanceRaw, decimals),
      balanceRaw: balanceRaw === null ? null : balanceRaw.toString(),
    },
    disclaimer: DISCLAIMER,
  });
}

// ---------- router ----------

async function handleRequest(request) {
  const url = new URL(request.url);

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    }});
  }

  if (url.pathname === '/' && request.method === 'GET') {
    return json({
      agent: 'Wallet Guard',
      description:
        'Scores the risk of an ERC20 token approval before you sign it. ' +
        'Send the token, spender, amount and (optionally) owner; get back SAFE / CAUTION / DANGER.',
      chains: ['ethereum', 'bsc', 'base'],
      endpoints: {
        'GET /health': 'liveness check',
        'POST /guard': 'risk assessment — see README for the request format',
      },
      example: {
        request: {
          chain: 'ethereum',
          token: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
          spender: '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
          amount: '1000',
        },
        curl: 'curl -X POST https://<your-worker>/guard -H "Content-Type: application/json" -d \'{"chain":"ethereum","token":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","spender":"0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D","amount":"1000"}\'',
      },
      disclaimer: DISCLAIMER,
    });
  }

  if (url.pathname === '/health' && request.method === 'GET') {
    return json({ ok: true });
  }

  if (url.pathname === '/guard') {
    if (request.method !== 'POST') {
      return json({ error: 'Method not allowed. Use POST /guard.' }, 405);
    }
    return handleGuard(request);
  }

  return json({ error: 'Not found. See GET / for usage.' }, 404);
}

export default {
  async fetch(request) {
    try {
      return await handleRequest(request);
    } catch (e) {
      // Never crash on an unexpected error — always answer JSON.
      return json({ error: 'Internal error.', details: String(e?.message || e) }, 500);
    }
  },
};
