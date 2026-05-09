# Fig — World ID + Attestations beta spec

Status: scaffold shipped, real APP_ID + Worker deploy pending.
Last updated: 2026-05.

## What this beta is

A working end-to-end loop for the Fig Earn thesis:

1. **Identity** — a Fig user signs in with World ID. Fig now knows this account is one specific verified human, not a sock-puppet.
2. **Attestation** — when that user hits a milestone (30-day savings streak, 90-day weight goal, etc.), Fig issues a signed attestation that says "this verified human met this milestone, on this date". The attestation does *not* leak raw transactions or weights.
3. **Public read** — the attestation is fetchable at a stable URL, keyed off the user's World ID `nullifier_hash`. Insurers, public programs, employers — anyone the user wants to share with — can read it without going through Fig's data path.

## What's in scope this round (shipped)

- Frontend "Sign in with World ID" via IDKit standalone widget in the Settings modal.
- Worker endpoint `POST /auth/worldid/verify` that calls Worldcoin's `developer.worldcoin.org/api/v2/verify/{app_id}` and stores `{nullifier_hash, verification_level}` against the user's Fig handle.
- Reverse-index `worldid:<nullifier_hash> → handle` so one verified human can't claim multiple Fig handles.
- Worker endpoint `POST /attestations` that signs `{nullifier_hash, kind, value, period_start, period_end}` with an HMAC-SHA256 key and stores the record.
- Worker endpoint `GET /attestations/:nullifier_hash` that returns all attestations for a verified human as JSON. Public, no auth.
- Frontend shows a "Verified human" badge in the auth chip after successful sign-in.
- Frontend triggers an attestation when the wiki detects a fresh 7-day streak (placeholder threshold; real thresholds come with the streak engine).

## What's deferred (next round)

- **On-chain attestations on World Chain.** The off-chain HMAC version is functionally complete and lets us iterate on the UX and partner conversations. Migrating to on-chain is mechanical from there: switch the signer from HMAC to ECDSA against a Cloudflare Worker–stored private key, and write to either a permissionless EAS schema or a tiny custom `Attestor` contract. Coinbase AgentKit can drive that step from the Worker; alternatively `viem` works directly inside the Worker runtime.
- **Production attestation schema.** Right now the kinds are loose strings. Before partner-readable, lock the schema (e.g. `streak.savings.30d`, `streak.workouts.30d`) and version it.
- **Bank data without Plaid.** Out of scope for World ID itself. Path is Open Banking (TrueLayer/Tink for UK/EU, Plaid alternatives like Finicity/MX for US, manual statement upload everywhere) — World ID gates the rebate eligibility, the bank data side is independent.
- **Health page integration.** The compiled React bundle in `health.html` is its own world; bringing it under central settings is the same parked task as the theme limitation.

## The Sybil-resistance argument (why this matters at all)

A rebate program funded by an insurer or a public-health body has exactly one fraud risk: one person claiming to be many. Every existing approach (KYC, Plaid, geofencing) is leaky and expensive.

World ID's `nullifier_hash` is deterministic per `(app_id, action, person)`. The same human verifying for the same action gets the same nullifier every time, but nothing about the nullifier reveals who they are or links them across apps. That's the unique unlock: insurers get a uniqueness guarantee with no PII transfer.

Concretely, with this beta in place a partner can:

```
GET https://fig-sync.<your>.workers.dev/attestations/0xabc...
→ [
    { kind: "streak.savings.30d", period_end: "2026-05-12", signature: "..." },
    { kind: "streak.workouts.30d", period_end: "2026-05-15", signature: "..." }
  ]
```

…and verify the signature against Fig's published HMAC key (or, in V2, a chain-resolvable signer). They never see the raw transactions, the weight in pounds, or the user's name — just "this verified human achieved these named milestones."

## Architecture

```
                ┌────────────────────────┐
                │   World App (phone)    │
                │   (orb-verified human) │
                └───────────┬────────────┘
                            │  ZK proof
                            ▼
   ┌──────────────────────────────────────────┐
   │  Fig home (index.html) — IDKit widget    │
   │  Settings → Identity → Sign in with WID  │
   └───────────┬──────────────────────────────┘
               │  proof + Fig token
               ▼
   ┌──────────────────────────────────────────┐
   │  Cloudflare Worker (worker.js)           │
   │  POST /auth/worldid/verify               │
   │   ├─ verify Fig handle/token             │
   │   ├─ POST developer.worldcoin.org/...    │  ─→ Worldcoin verify API
   │   ├─ store {nullifier, level} in KV      │
   │   └─ reverse-index nullifier → handle    │
   └───────────┬──────────────────────────────┘
               │
               │  later, when a streak fires:
               ▼
   ┌──────────────────────────────────────────┐
   │  POST /attestations                      │
   │   ├─ verify Fig token                    │
   │   ├─ build {nullifier,kind,value,period} │
   │   ├─ HMAC-SHA256 sign with ATTEST_KEY    │
   │   └─ store attest:<nullifier>:<kind>     │
   └──────────────────────────────────────────┘
                            │
                            ▼  public read
   ┌──────────────────────────────────────────┐
   │  GET /attestations/:nullifier            │
   │   → JSON list of signed attestations     │
   └──────────────────────────────────────────┘
```

## Worker setup checklist

```bash
cd ~/Desktop/Fig/worker

# 1. WORLD_ID_APP_ID  ← from developer.worldcoin.org (see registration steps)
wrangler secret put WORLD_ID_APP_ID

# 2. ATTEST_KEY  ← any 32-byte random hex; used to HMAC-sign attestations
openssl rand -hex 32 | wrangler secret put ATTEST_KEY

# 3. Deploy
wrangler deploy
```

## Worldcoin Developer Portal — registration

1. Go to <https://developer.worldcoin.org>.
2. Sign in with your World App (you'll need to pair via QR — same login your phone wallet uses).
3. **Create app** → name `Fig`, type `Cloud`, environment `Production` (or `Staging` for the beta — both work the same way for this verification flow).
4. After creation, you'll see an **App ID** that starts with `app_…` — copy it.
5. **Actions** tab → **Create action** → name `verify-human`, max verifications `Unlimited`. This action is what the user signs against; same human verifying the same action always returns the same `nullifier_hash`.
6. Run `wrangler secret put WORLD_ID_APP_ID` from the worker folder and paste the App ID.
7. Frontend reads the App ID from a small `/config` endpoint on the Worker (so we never have to bake it into the static HTML and you can rotate it without a deploy).

## Open questions / known unknowns

- Same person, multiple Fig accounts: today our reverse index allows the *first* claim to win. Should subsequent attempts be rejected outright, or merge data into the original handle?
- Attestation revocation: if a user later wants to retract an attestation (privacy preference change), do we delete or just mark `revoked_at`? Lean toward soft delete with a public revocation list.
- World ID Lite (phone-verified, no Orb): Fig should accept it but tag attestations as `verification_level: "device"` vs `"orb"` so partners can choose what they fund.
- For US bank data without Plaid, the realistic short-term path is manual statement upload (which Fig already supports) plus optional Finicity/MX integration. Open Banking is the long game.
- AgentKit specifically: useful when we move attestations on-chain (it can drive a wallet on World Chain from a Worker). Not on the critical path until then.
