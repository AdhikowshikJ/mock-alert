# atlas-vendor-mock

A mock vendor backend for testing `/data-puller` generated Atlas templates against deterministic, controlled API responses.

## What it is

A Node/Express service that hosts 8 fake vendor APIs at distinct path prefixes. When a generated Atlas data-puller template runs against this mock, it gets canned tokens + paginated alert data + multi-step job responses + 429 rate limits + 404 enrichment failures — exactly the scenarios the 8 briefs in `Integration-Skill-noP3/evals/briefs/` describe.

The mock is purely a **vendor stand-in**. It doesn't execute Atlas templates, doesn't interpret YAML, doesn't replace any platform component. Atlas runs templates the normal way (Cooper / TARS / etc.); they just happen to talk to this mock instead of a real vendor.

## Route map

| Path prefix | Brief | Scenario |
|---|---|---|
| `/vanilla-bearer` | 1 | Static Bearer + single GET, no pagination |
| `/cobalt` | 2 | Literal `ApiToken` header + boolean `has_more` pagination |
| `/vortex` | 3 | OAuth2 client_credentials + cursor pagination |
| `/nimbus` | 4 | Multi-step submit/poll/results (state → `COMPLETED` after 2 polls) |
| `/aegis` | 5 | List endpoint (cursor) + per-id detail fetch |
| `/bastion` | 6 | Session-login (cookie) + offset/count pagination |
| `/pulse` | 7 | Rate limit 5 req/min → 429 with `Retry-After` |
| `/helix` | 8 | Cursor-paginated alerts + flaky enrichment (assets ending `00` → 404) |
| `/sentinelshield` | wb A | Writeback — static `X-Api-Key` + single `PATCH` close |
| `/nimbusguard` | wb B | Writeback — OAuth2 client_credentials + `PATCH` close |
| `/threatnexus` | wb C | Writeback — `ApiToken` + multi-step (close incident, then add note) |
| `/lumen` | wb D | Writeback — OAuth2 + single GraphQL mutation |
| `/falcon` | unified | OAuth2 (shared token) · cursor pull + single-call close |
| `/sentryx` | unified | ApiToken · offset pull + multi-step close+note |
| `/skylux` | unified | OAuth2 · one GraphQL endpoint (query=pull, mutation=writeback) |
| `/ironclad` | unified | X-Api-Key · has_more pull + close (404 / idempotent edges) |
| `/warden` | unified | session cookie · offset pull + cookie-auth close (401 edge) |
| `/rampart` | unified | Bearer · single pull + close, rate-limited 5/min on both (429) |
| `/ccs/v4/secret/:name` | all | CCS v4 secret stub (per-integration-name canned blob) |
| `/_debug/requests` | — | Ring buffer of recent inbound requests (for verification) |
| `/_debug/clear` | — | POST to clear the request log |
| `/_debug/writebacks` | — | Ledger of accepted writebacks (for verification) |
| `/_debug/clear-writebacks` | — | POST to clear the writeback ledger |
| `/_debug/alerts/:vendor` | — | Current alert store for a unified vendor (proves the round-trip) |
| `/_debug/reseed` | — | POST to reset all unified-vendor alert stores |

### Unified vendors (one vendor does BOTH pull and writeback)

Real vendors pull alerts **and** accept writebacks on the same alert. These six expose both
directions over a **single CCS secret and a shared in-memory alert store**, so the id you pull is
the id you close — and `/_debug/alerts/:vendor` (or a re-pull) shows the status flip. This is the
thing the split pull-only / writeback-only vendors can't prove: the **id round-trip**.

| Vendor | Integration name | Auth | Pull | Writeback | Edges exercised |
|---|---|---|---|---|---|
| falcon | `FALCON` | OAuth2 (token shared by both) | cursor | `PATCH /falcon/alerts` (composite_ids) | token reuse; id round-trip |
| sentryx | `SENTRYX` | ApiToken | offset | `POST .../threats/resolve` + `.../:id/notes` | multi-step; account_id from secret; best-effort note |
| skylux | `SKYLUX` | OAuth2 | GraphQL `query` | GraphQL `mutation` (same endpoint) | one endpoint both ways |
| ironclad | `IRONCLAD` | X-Api-Key | has_more | `PATCH .../detections/:id` | close unknown id → 404; re-close → idempotent no-op |
| warden | `WARDEN` | session cookie | offset | `POST .../events/:id/close` | cookie reused for writeback; missing cookie → 401 |
| rampart | `RAMPART` | Bearer static | single | `PATCH .../detections/:id` | rate limit 5/min applies to writeback too → 429 Retry-After |

```bash
# falcon round-trip: pull an id, close it, see the status flip
TOK=$(curl -s -X POST $BASE/falcon/oauth2/token -d 'grant_type=client_credentials&client_id=c&client_secret=s' | jq -r .access_token)
curl -s $BASE/falcon/alerts -H "Authorization: Bearer $TOK"            # pull → composite_id
curl -s -X PATCH $BASE/falcon/alerts -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' -d '{"composite_ids":["falcon:0001:det"],"action":"resolve"}'
curl -s $BASE/_debug/alerts/falcon                                     # → that alert is now "closed"
```

### Writeback endpoints (close-alert / response-action targets)

These back the **write-backs** skill — the close/update calls a generated vendor handler makes.
Each covers one auth/flow archetype. Credentials come from CCS v4 (`/ccs/v4/secret/<NAME>`):
integration names `SENTINELSHIELD_EDR`, `NIMBUSGUARD_CLOUD`, `THREATNEXUS_XDR`, `LUMEN_CNAPP`.

| Archetype | Vendor | Auth | Endpoint(s) |
|---|---|---|---|
| **A** static key, single call | sentinelshield | `X-Api-Key` | `PATCH /sentinelshield/api/v2/detections/resolve` |
| **B** OAuth2, single call | nimbusguard | Bearer (after token) | `POST /nimbusguard/oauth2/token`, `PATCH /nimbusguard/v1/findings/:id` |
| **C** multi-step | threatnexus | `ApiToken` | `POST /threatnexus/web/api/v2.1/incidents/resolve`, `POST /threatnexus/web/api/v2.1/incidents/:id/notes` |
| **D** GraphQL | lumen | Bearer (after token) | `POST /lumen/oauth2/token`, `POST /lumen/graphql` |

```bash
# A — static API key
curl -X PATCH http://localhost:3000/sentinelshield/api/v2/detections/resolve \
  -H "X-Api-Key: k" -H "Content-Type: application/json" \
  -d '{"detection_ids":["det-1"],"resolution":"benign","note":"closed by atlas"}'

# B — OAuth then close
TOK=$(curl -s -X POST http://localhost:3000/nimbusguard/oauth2/token \
  -d "grant_type=client_credentials&client_id=c&client_secret=s" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
curl -X PATCH http://localhost:3000/nimbusguard/v1/findings/find-9 \
  -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"state":"resolved","classification":"false_positive","determination":"benign"}'

# verify what was written back
curl http://localhost:3000/_debug/writebacks
```

## Local dev

```bash
npm install
npm start                 # → http://localhost:3000
```

Smoke-test a few endpoints:

```bash
curl http://localhost:3000/                                          # route map

curl -H "Authorization: Bearer xyz" \
  http://localhost:3000/vanilla-bearer/v1/alerts                     # brief 1

curl -H "Authorization: ApiToken xyz" \
  "http://localhost:3000/cobalt/api/v2/detections?offset=0&limit=10" # brief 2

curl -X POST -d "grant_type=client_credentials&client_id=a&client_secret=b" \
  http://localhost:3000/vortex/oauth/token                           # brief 3 step 1

curl http://localhost:3000/ccs/v4/secret/VANILLA_BEARER              # CCS mock
```

Inspect what arrived at the mock:

```bash
curl http://localhost:3000/_debug/requests?limit=10
```

## Deploy to Render

1. **Push this folder to a GitHub repo** (Render needs a Git source — no ZIP upload). Repo can be private.
2. On Render: **New → Web Service → Connect your repo**.
3. Render auto-detects `render.yaml`. Click **Create Web Service**.
4. Once the URL is live (e.g. `https://atlas-vendor-mock.onrender.com`), open the service's **Environment** tab and set:
   ```
   PUBLIC_BASE_URL = https://atlas-vendor-mock.onrender.com
   ```
   This makes the CCS v4 endpoint return `instance_url` values that point back at this service (so generated templates self-reference correctly).
5. **Free tier sleeps after 15 min idle** (30–60s cold-start on first hit). Upgrade to Starter ($7/mo) if cold-starts become annoying during testing.

## How to use it with Atlas

Two paths depending on where Atlas runs:

**Atlas int (recommended for now):**
- Provision CCS v4 secret entries under integration names: `VANILLA_BEARER`, `COBALT`, `VORTEX`, `NIMBUS`, `AEGIS`, `BASTION`, `PULSE`, `HELIX`.
- Each entry's fields should match what `lib/fixtures.js > ccsSecrets` shows for that integration.
- `instance_url` (or `console_url` / `api_url`) points at the relevant path on the deployed mock.
- Run `/data-puller <vendor_name> evals/briefs/<n>_<brief>.md` against the brief → generated templates use the integration name → Atlas pulls the right CCS secret → it points at the mock → mock returns canned data.
- Use `/_debug/requests` on the mock to verify what Atlas sent.

**Local Atlas** (future):
- Compile from `external/atlas/` source.
- Configure CCS replacement to point at `/ccs/v4/secret/...` on the mock.
- All-local testing loop.

## Verifying correctness — what to look for

After Atlas runs a generated template against the mock, two signals tell you pass/fail:

1. **Atlas's pull log / output** — Did the pipeline succeed? Did it ingest the expected number of canned alerts? Are the alerts shaped the way the brief says?
2. **The mock's `/_debug/requests` log** — Did Atlas hit the right endpoints with the right headers / query params / body?

Examples of behavioral failures the mock catches that static assertions miss:
- Header literal wrong (`Bearer` instead of `ApiToken`) → mock returns 401, Atlas sees 0 alerts.
- Cursor query param sent with literal `<no value>` (Go-template nil bug) → mock returns weird page, pull gets stuck.
- `wait-on.condition` polls the wrong path → mock never returns `COMPLETED` → Atlas hits max-attempts and aborts.
- Pagination loop never terminates → mock keeps serving pages, Atlas crashes or times out.

## What's intentionally NOT here

- **Real secret validation.** Any non-empty token is accepted. We test request *shape*, not credentials.
- **Persistence.** All state (jobs, sessions, rate-limit counters, OAuth tokens) lives in-memory and clears on restart. Intentional for repeatable test runs.
- **Multi-tenant isolation.** One mock instance, all eval scenarios on the same service. Distinct path prefixes keep them separate.
- **HTTPS in dev.** Local runs are HTTP. Render adds TLS automatically.

## Adding a new scenario

To add a 9th vendor:
1. Append fixture data to `lib/fixtures.js > ccsSecrets` (new integration name) + a fixture array.
2. Add `routes/<newVendor>.js`.
3. Mount in `server.js`: `app.use('/<path>', require('./routes/<newVendor>'));`.
4. Update this README's route map.
5. Add a brief to `Integration-Skill-noP3/evals/briefs/`.
