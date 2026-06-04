const express = require('express');
const cookieParser = require('cookie-parser');
const { requestLogger, getRecentRequests, clearRequests } = require('./lib/requestLog');

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
      '/ccs/v4/secret/:name': 'CCS v4 mock — canned secret blob per integration name',
      '/_debug/requests':     'GET: ring buffer of recent requests (for verification)',
      '/_debug/clear':        'POST: clear the request log buffer'
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

// Request log inspection — for verifying what Atlas sent
app.get('/_debug/requests', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  res.json(getRecentRequests(limit));
});

app.post('/_debug/clear', (req, res) => {
  clearRequests();
  res.json({ cleared: true });
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
