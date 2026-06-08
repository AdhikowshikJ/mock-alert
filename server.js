const express = require('express');
const cookieParser = require('cookie-parser');
const { requestLogger, getRecentRequests, clearRequests } = require('./lib/requestLog');
const { getWritebacks, clearWritebacks } = require('./lib/state');
const alertStore = require('./lib/alertStore');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(requestLogger);

// Health check + route map
app.get('/', (req, res) => {
  res.json({
    name: 'atlas-vendor-mock',
    description: 'Mock vendor backend for /data-puller eval scenarios',
    routes: {
      '/vanilla-bearer': 'brief 1 — Bearer + single GET (no pagination)',
      '/cobalt':         'brief 2 — ApiToken literal header + has_more pagination',
      '/vortex':         'brief 3 — OAuth2 client_credentials + cursor',
      '/nimbus':         'brief 4 — multi-step submit/poll/results',
      '/aegis':          'brief 5 — list + per-id detail (cursor on list)',
      '/bastion':        'brief 6 — session login (cookie) + offset/count',
      '/pulse':          'brief 7 — rate limit (5/min) → 429 Retry-After',
      '/helix':          'brief 8 — optional sidecar (asset IDs ending 00 → 404)',
      '/sentinelshield': 'writeback A — static X-Api-Key + single PATCH close',
      '/nimbusguard':    'writeback B — OAuth2 client_credentials + PATCH close',
      '/threatnexus':    'writeback C — ApiToken + multi-step close incident + add note',
      '/lumen':          'writeback D — OAuth2 + single GraphQL mutation',
      '/falcon':         'UNIFIED — OAuth2; cursor pull + single-call close (shared token, id round-trip)',
      '/sentryx':        'UNIFIED — ApiToken; offset pull + multi-step close+note',
      '/skylux':         'UNIFIED — OAuth2; one GraphQL endpoint: query=pull, mutation=writeback',
      '/ironclad':       'UNIFIED — X-Api-Key; has_more pull + close (404 + idempotent edges)',
      '/warden':         'UNIFIED — session cookie; offset pull + cookie-auth close (401 edge)',
      '/rampart':        'UNIFIED — Bearer; single pull + close, rate-limited 5/min on BOTH (429)',
      '/ccs/v4/secret/:name': 'CCS v4 mock — canned secret blob per integration name',
      '/_debug/requests':     'GET: ring buffer of recent requests (for verification)',
      '/_debug/clear':        'POST: clear the request log buffer',
      '/_debug/writebacks':   'GET: ledger of accepted writebacks (for verification)',
      '/_debug/clear-writebacks': 'POST: clear the writeback ledger',
      '/_debug/alerts/:vendor':   'GET: current alert store for a unified vendor (proves pull↔writeback round-trip)',
      '/_debug/reseed':           'POST: reset all unified-vendor alert stores to seed state'
    }
  });
});

// Mount vendor routes
app.use('/vanilla-bearer', require('./routes/vanillaBearer'));
app.use('/cobalt',         require('./routes/apiKeyHasMore'));
app.use('/vortex',         require('./routes/oauth2Cursor'));
app.use('/nimbus',         require('./routes/multiStepPoll'));
app.use('/aegis',          require('./routes/listThenSplit'));
app.use('/bastion',        require('./routes/sessionLogin'));
app.use('/pulse',          require('./routes/rateLimitRetry'));
app.use('/helix',          require('./routes/sidecarOptional'));
app.use('/ccs',            require('./routes/ccs'));

// Writeback (close-alert / response-action) vendor routes — all archetypes
app.use('/sentinelshield', require('./routes/wbStaticApiKey'));  // A: static API key
app.use('/nimbusguard',    require('./routes/wbOauth'));         // B: OAuth2 + single call
app.use('/threatnexus',    require('./routes/wbMultiStep'));     // C: ApiToken + close + note
app.use('/lumen',          require('./routes/wbGraphql'));       // D: OAuth2 + GraphQL

// UNIFIED vendor routes — same vendor does BOTH pull and writeback (shared alert store)
app.use('/falcon',   require('./routes/falcon'));    // OAuth2; cursor pull + single close
app.use('/sentryx',  require('./routes/sentryx'));   // ApiToken; offset pull + multi-step close+note
app.use('/skylux',   require('./routes/skylux'));    // OAuth2; GraphQL query=pull, mutation=writeback
app.use('/ironclad', require('./routes/ironclad'));  // X-Api-Key; has_more pull + close (404/idempotent)
app.use('/warden',   require('./routes/warden'));    // session cookie; offset pull + cookie close
app.use('/rampart',  require('./routes/rampart'));   // Bearer; rate-limited pull + close (429)

// Request log inspection — for verifying what Atlas sent
app.get('/_debug/requests', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  res.json(getRecentRequests(limit));
});

app.post('/_debug/clear', (req, res) => {
  clearRequests();
  res.json({ cleared: true });
});

// Writeback ledger inspection — for verifying what Atlas wrote back
app.get('/_debug/writebacks', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  res.json(getWritebacks(limit));
});

app.post('/_debug/clear-writebacks', (req, res) => {
  clearWritebacks();
  res.json({ cleared: true });
});

// Unified-vendor alert store inspection — proves the pull↔writeback round-trip
app.get('/_debug/alerts/:vendor', (req, res) => {
  res.json({ vendor: req.params.vendor, alerts: alertStore.all(req.params.vendor) });
});

app.post('/_debug/reseed', (req, res) => {
  alertStore.seedAll();
  res.json({ reseeded: true });
});

// 404 catch-all
app.use((req, res) => {
  res.status(404).json({
    error: 'no such route',
    path: req.originalUrl,
    hint: 'GET / for the route map'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`atlas-vendor-mock listening on :${PORT}`);
  if (process.env.PUBLIC_BASE_URL) {
    console.log(`PUBLIC_BASE_URL = ${process.env.PUBLIC_BASE_URL}`);
  }
});
