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
| `/ccs/v4/secret/:name` | all | CCS v4 secret stub (per-integration-name canned blob) |
| `/_debug/requests` | — | Ring buffer of recent inbound requests (for verification) |
| `/_debug/clear` | — | POST to clear the request log |

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
