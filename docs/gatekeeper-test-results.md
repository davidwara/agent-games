# Test Results — Proof Gatekeeper Agent

Tanggal: 15 Nov 2026, ~07:16–07:35 WIB. Perintah: `node test-agent.js`
di `gatekeeper/` (secret HMAC throwaway, tanpa Kurier).

## Tes lokal: 13/13 PASS

| # | Kasus | Hasil |
|---|-------|-------|
| 0 | Preflight → `{ok:true, protocolVersion:"v1"}` + response signature valid | PASS (14 ms) |
| 1 | Valid → APPROVE / VALID_CONDITION + proof terverifikasi lokal | PASS (1.119 ms — termasuk load wasm pertama) |
| 2 | Redelivery task_id sama → body response identik (cache) | PASS |
| 3 | VK_SUBSTITUTION → REJECT + proof terverifikasi (decision=0) | PASS (400 ms) |
| 4 | THRESHOLD_MISMATCH → REJECT + proof terverifikasi (decision=0) | PASS (299 ms) |
| 5 | EXPIRED_CONDITION → REJECT + proof terverifikasi (decision=0) | PASS (402 ms) |
| 6 | RECIPIENT_MISMATCH → REJECT + proof terverifikasi (decision=0) | PASS (307 ms) |
| 7 | AMOUNT_OVERFLOW → REJECT + proof terverifikasi (decision=0) | PASS (290 ms) |
| 8 | PROOF_REUSED (proof_tx sama, task baru) → REJECT, TANPA proof | PASS (4 ms) |
| 9 | Signature HMAC salah → HTTP 401 | PASS |
| 10 | JSON malformed (HMAC valid) → 400 REJECT / INVALID_TASK | PASS |
| 11 | Envelope type tidak dikenal → 400 REJECT / INVALID_TASK | PASS |
| 12 | Boundary (balance==min, amount==max, block==expiry−1) → APPROVE + proof terverifikasi | PASS (281 ms) |

Setiap proof dicek dengan `snarkjs.groth16.verify(verification_key.json,
public_signals, proof)` — semua `OK`. Public signal berjumlah 13 dan
`public_signals[11]` (decision) = `"1"` untuk APPROVE, `"0"` untuk REJECT.

Waktu per task setelah warm-up: ~0,3–0,4 detik (jauh di bawah deadline 60 detik).
Tanpa Kurier (belum ada API key), `proof_tx` = echo input `proof_tx`.

Catatan run pertama: 9/13 — 4 kasus trap gagal BUKAN karena agen, melainkan
data tes yang memakai `proof_tx` yang sama untuk semua kasus sehingga
seen-set menganggapnya PROOF_REUSED (perilaku agen sudah benar). Tes diperbaiki
dengan `proof_tx` unik per kasus → 13/13.

## Verifikasi circuit (pra-tes)

- `snarkjs zkey export verificationkey` → protokol groth16, kurva bn128,
  public signal = 13.
- `groth16.fullProve({})` → error `Not all inputs have been set. Only 0 out of 13`
  (memastikan 13 input).
- Nama 13 signal dikonfirmasi lewat artefak + pembuktian (bukan dari dokumen —
  halaman /build tidak mencantumkannya):
  `taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, salt`.

## Uji endpoint publik (tunnel) — GAGAL, dua jalur diblokir sandbox

1. **Cloudflare Quick Tunnel** (`cloudflared tunnel --url http://127.0.0.1:8787`):
   `failed to request quick Tunnel: ... tls: first record does not look like a TLS handshake`.
   `curl https://api.trycloudflare.com/tunnel` → HTTP 403.
2. **localhost.run via SSH**: `Connection reset by 198.19.0.1 port 3128` (proxy
   sandbox memblokir SSH port 22 keluar).
3. **Cloudflare edge umumnya diblokir dari VM ini**: `dash.cloudflare.com` → 403,
   `api.cloudflare.com` → 403, `region1.argotunnel.com` → 403. Jadi **named tunnel
   Cloudflare juga tidak bisa jalan dari VM ini**.
4. Yang MASIH bisa dijangkau: `github.com` → 200, `api.kurier.xyz` → 404 (root path,
   artinya reachable), `vercel.com` → 200, `api.vercel.com` → 403 (tanpa token —
   normal).

**Kesimpulan hosting: agen TIDAK BISA diekspos ke publik dari VM ini via tunnel.
Jalur yang tersisa: deploy ke Vercel (seperti agen referensi yang terbukti jalan)
atau hosting lain yang bisa di-deploy dari repo GitHub via browser. Lihat README.md.**

## Yang BELUM dites (butuh langkah parent)

- Preflight dari platform (dashboard) — butuh endpoint publik + HMAC secret asli.
- Practice task dari platform — butuh endpoint publik + HMAC secret asli.
- Kurier submit — butuh `KURIER_API_KEY` (daftar di kurier.xyz).
- Behaviour saat Round 3 live (17:30 WIB 15 Nov) — butuh semua di atas selesai.
