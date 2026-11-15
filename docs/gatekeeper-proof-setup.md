# Proof Gatekeeper — Mekanisme Proof Resmi

Dokumen ini mencatat DENGAN PASTI mekanisme proof yang dipakai agen ini,
semuanya diverifikasi dari dokumen resmi + artefak circuit + pengujian lokal.
Bukan asumsi.

## Sumber resmi

- Build Guide: `https://agentgames.zkverify.io/build`
- Guide: `https://agentgames.zkverify.io/guide` · Rules: `https://agentgames.zkverify.io/rules`
- Event: `https://agentgames.zkverify.io/events/proof-gatekeeper`
- Circuit info (JSON): `https://agentgames.zkverify.io/api/circuit-info`
- Kurier: `https://api.kurier.xyz/api/v1` (endpoint dari Build Guide)

## 1. Circuit (Groth16 / BN128, Circom 2.x)

- `circuits/gatekeeper.wasm` (1.755.820 byte) + `circuits/gatekeeper_final.zkey`
  (309.750 byte) — diunduh dari `https://agentgames.zkverify.io/circuits/`.
- `vkHash` (terdaftar di zkVerify mainnet): `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`
- `circuits/verification_key.json` diekstrak dari `.zkey` (`snarkjs zkey export verificationkey`).
  Jumlah public signal = 13 (`len(vk.IC) - 1`).
- **13 input signal** (dikonfirmasi lewat `getInputSize()` pada wasm + pembuktian):
  `taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, salt`
- `salt` adalah SATU-SATUNYA input privat. 12 sisanya publik.
- **Urutan public signal** (13): `[commitment, registeredVkHash, proofVkHash,
  minimum, publicBalance, expiryBlock, currentBlock, recipient,
  conditionRecipient, amount, maxTransfer, decision, taskId]`
  dengan `commitment = Poseidon(taskId, salt)` sebagai satu-satunya output circuit.
- **Semantik circuit (terbukti eksperimental):** `decision` harus sama dengan AND
  dari 5 pengecekan lapangan (VK cocok, balance ≥ minimum, belum expired,
  recipient cocok, amount ≤ max). Keputusan yang salah TIDAK BISA menghasilkan
  witness — `fullProve` gagal. Jadi proof yang valid otomatis membuktikan
  keputusan benar (untuk field yang diberikan).

## 2. Konversi nilai envelope → field element

Aturan yang dipakai agen (dan diverifikasi lewat pembuktian):
- Hex (`0x...`) → `BigInt(hex)` lalu `mod p` (p = prima BN128
  `21888242871839275222246405745257275088548364400416034343698204186575808495617`).
  Mod-p mempertahankan kesamaan (equality), yang merupakan semua yang dicek circuit.
- String desimal → `BigInt(desimal)`.
- String bebas (mis. `task_id` seperti `gk_8d31_x`) → `SHA-256(string)` → BigInt → mod p.
- Bilangan (`minimum`, `publicBalance`, `expiryBlock`, `currentBlock`, `amount`,
  `maxTransfer`) → string desimal.
- `decision`: `"APPROVE"` → `"1"`, `"REJECT"` → `"0"`.
- `salt`: `HMAC-SHA256(secret, "gatekeeper-salt:" + task_id)` → BigInt → mod p.
  Deterministik per task (redelivery menghasilkan input proof yang sama) dan
  terikat secret sehingga tidak bisa ditebak pihak ketiga.

## 3. HMAC (otentikasi request/response)

- Header: `x-agent-games-signature`.
- Request: `HMAC-SHA256(secret, RAW body)` — secret dipakai sebagai string UTF-8
  ("conventional reading"; dokumen tidak menetapkan encoding secara eksplisit).
  Digest hex lowercase untuk response; verifikasi inbound menerima hex ATAU
  base64 (opsional prefix `sha256=`), dibanding dengan `timingSafeEqual`.
- Verifikasi dilakukan terhadap RAW body SEBELUM parsing JSON. Gagal → HTTP 401.
- Response juga ditandatangani: `x-agent-games-signature: HMAC-SHA256(secret, raw response body)` (hex).
- Secret: 32-byte dari dashboard ("Rotate Secret"), lewat env
  `AGENT_GAMES_HMAC_SECRET` (atau alias `GATEKEEPER_HMAC_SECRET`, atau file
  `~/.agent-games/gatekeeper-hmac.txt`). TIDAK PERNAH di-hardcode / di-commit.

## 4. Format request & response

Request (POST ke endpoint terdaftar, mis. `/agent`):
```json
{
  "type": "agent-games.proof-gatekeeper.v1",
  "task_id": "gk_8d31_...",
  "mode": "competition",
  "issued_at": "<issued-at>",
  "deadline_at": "<deadline-at>",
  "input": {
    "registered_vk": "0x7d...91", "proof_vk": "0x13...aa",
    "minimum": "1000", "public_balance": "1460",
    "expiry_block": 8430000, "current_block": 8420000,
    "recipient": "0xDe42...9f01", "condition_recipient": "0xDe42...9f01",
    "amount": "500", "max_transfer": "1000",
    "proof_tx": "0xa8...2c"
  }
}
```

Preflight: request `{ "type": "agent-games.preflight.v1", "agent_id": "...",
"issued_at": "...", "nonce": "..." }` → response `{ "ok": true,
"protocolVersion": "v1" }` (ditandatangani).

Response task:
```json
{ "decision": "APPROVE" | "REJECT", "reason_code": "<kode>",
  "proof": { "pi_a": [...], "pi_b": [[...]], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
  "public_signals": ["<commitment>", "<registeredVkHash>", "...", "<decision>", "<taskId>"],
  "proof_tx": "<tx hash Kurier, atau echo input proof_tx>" }
```
- `proof` + `public_signals` WAJIB pada semua task yang provable; tidak ada /
  tidak valid → −2. Pengecualian terdokumentasi: `PROOF_REUSED` (tidak ada proof
  untuk disubmit — response hanya decision + reason_code + proof_tx echo).

## 5. Kebijakan keputusan (urutan cek — penting!)

1. `proof_vk != registered_vk` → REJECT / `VK_SUBSTITUTION`
2. `proof_tx` sudah di seen-set → REJECT / `PROOF_REUSED` (tanpa proof)
3. `public_balance < minimum` → REJECT / `THRESHOLD_MISMATCH`
4. `current_block >= expiry_block` → REJECT / `EXPIRED_CONDITION`
5. `recipient != condition_recipient` → REJECT / `RECIPIENT_MISMATCH`
6. `amount > max_transfer` → REJECT / `AMOUNT_OVERFLOW`
7. Selain itu → APPROVE / `VALID_CONDITION`

Batas (boundary): balance == minimum LULUS, amount == max_transfer LULUS,
current_block == expiry_block − 1 LULUS (current < expiry).

Skor: benar +12 · salah approve −6 · salah reject −3 · timeout −2 ·
proof hilang/invalid −2 · bonus reliabilitas +0..+5. Deadline jawab 60 detik.

## 6. Kurier (submit proof ke zkVerify mainnet)

- `POST https://api.kurier.xyz/api/v1/submit-proof/{KURIER_API_KEY}`
  body: `{ proofType: "groth16", vkRegistered: true,
  proofOptions: { library: "snarkjs", curve: "bn128" },
  proofData: { proof, publicSignals, vk: "<gatekeeper vkHash>" } }`
  → `{ jobId, optimisticVerify }`. `vkRegistered: true` karena vkHash gatekeeper
  SUDAH terdaftar di mainnet — tidak perlu register VK.
- `GET https://api.kurier.xyz/api/v1/job-status/{KURIER_API_KEY}/{jobId}`
  → `{ status, txHash, transactionInfo: { txHash } }`.
  Lifecycle: `Queued → Valid → Submitted → IncludedInBlock → Finalized | Failed`.
- **txHash sudah ada sejak status `Submitted` (~4 detik); Finalized ~27 detik.**
  Agen mem-poll maksimal 15 detik dan mengembalikan txHash begitu tersedia —
  TIDAK menunggu finalisasi (finalisasi lanjut di sisi Kurier). Tanpa
  `KURIER_API_KEY`, langkah ini dilewati dan `proof_tx` = echo input; proof
  tetap digenerate dan dikembalikan di response.
- BUTUH API KEY mainnet dari kurier.xyz (pendaftaran akun) — belum dimiliki.

## 7. Aturan lain yang ditegakkan agen

- Fail closed: envelope malformed, error internal, atau proof gagal → REJECT.
- Idempotensi: `task_id` adalah idempotency key — redelivery dijawab dari cache
  (tidak dievaluasi ulang, supaya tidak keliru dianggap proof reuse).
- Seen-set `proof_tx` persisten di file JSON (`data/seen.json`) — reuse terdeteksi
  bahkan berhari-hari kemudian.
- Deadline internal lunak 45 detik (di bawah batas keras 60 detik platform).
- Endpoint harus HTTPS publik; tanpa localhost / IP privat / custom port.
