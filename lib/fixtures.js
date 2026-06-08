// Canned alert / event data for each vendor + CCS v4 secret blobs.
// Sizes chosen to exercise pagination across multiple pages where relevant.

// ─── Vanilla Bearer (brief 1) — no pagination, 5 alerts ──────────────────────
const vanillaBearerAlerts = [
  { id: 'vb-001', created_at: '2026-05-30T12:34:56Z', severity: 'high',     rule_name: 'Suspicious Login',           src_ip: '10.0.0.42',   user: 'jdoe' },
  { id: 'vb-002', created_at: '2026-05-30T12:35:10Z', severity: 'medium',   rule_name: 'Multiple Failed Logins',     src_ip: '10.0.0.42',   user: 'jdoe' },
  { id: 'vb-003', created_at: '2026-05-30T12:36:22Z', severity: 'low',      rule_name: 'Unusual Geo',                src_ip: '203.0.113.5', user: 'asmith' },
  { id: 'vb-004', created_at: '2026-05-30T12:37:00Z', severity: 'high',     rule_name: 'Privilege Escalation',       src_ip: '10.0.0.99',   user: 'svc-deploy' },
  { id: 'vb-005', created_at: '2026-05-30T12:38:15Z', severity: 'critical', rule_name: 'Lateral Movement Detected',  src_ip: '10.0.0.42',   user: 'jdoe' }
];

// ─── Cobalt (brief 2) — 30 detections, 10/page, has_more boolean ────────────
const cobaltDetections = Array.from({ length: 30 }, (_, i) => ({
  id: `det-${String(i + 1).padStart(4, '0')}`,
  occurred_at: `2026-05-30T${String(12 + Math.floor(i / 10)).padStart(2, '0')}:${String((i * 7) % 60).padStart(2, '0')}:56Z`,
  severity: ['low', 'medium', 'high', 'critical'][i % 4],
  category: ['exfiltration', 'lateral_movement', 'credential_access', 'persistence'][i % 4],
  asset_id: `i-${String(i + 100).padStart(4, '0')}`,
  description: `Detection ${i + 1}: anomalous activity`
}));

// ─── Vortex (brief 3) — 25 threats, 10/page, cursor pagination ──────────────
const vortexThreats = Array.from({ length: 25 }, (_, i) => ({
  id: `thr-${'abcd'[i % 4].repeat(4)}-${String(i + 1000).padStart(4, '0')}`,
  detected_at: `2026-05-30T12:${String((i * 3) % 60).padStart(2, '0')}:56Z`,
  severity: ['low', 'medium', 'high'][i % 3],
  name: ['PowerShell.Suspicious.Encoded', 'Trojan.Generic', 'Backdoor.Linux'][i % 3],
  endpoint_id: `ep-${String(i).padStart(4, '0')}`,
  hostname: `win10-prod-${String(i % 10).padStart(2, '0')}`
}));

// ─── Nimbus (brief 4) — 100 events, returned all-at-once after poll ─────────
const nimbusEvents = Array.from({ length: 100 }, (_, i) => ({
  event_id: `evt-${String(i + 1).padStart(4, '0')}`,
  ts: `2026-05-30T12:${String(i % 60).padStart(2, '0')}:56Z`,
  severity: ['low', 'medium', 'high'][i % 3],
  rule: 'Failed login from unusual geo',
  user: `user${i % 10}`,
  geo_country: ['US', 'RU', 'CN', 'DE'][i % 4]
}));

// ─── Aegis (brief 5) — 15 alert IDs, 5/page on list; detail on demand ──────
const aegisAlertIds = Array.from({ length: 15 }, (_, i) => `a-${String(i + 1).padStart(3, '0')}`);

function aegisAlertDetail(id) {
  return {
    id,
    created_at: '2026-05-30T12:34:56Z',
    severity: 'high',
    type: 'lateral_movement',
    source_host: `host-${id.slice(2)}`,
    target_host: 'dc-01',
    raw_evidence: '<binary>'
  };
}

// ─── Bastion (brief 6) — 1247 events, offset/count pagination ────────────────
const bastionEvents = Array.from({ length: 1247 }, (_, i) => ({
  event_id: `ev-${String(i + 1).padStart(5, '0')}`,
  ts: `2026-05-30T${String(12 + Math.floor(i / 60) % 24).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:56Z`,
  type: ['authentication_failure', 'authentication_success', 'lockout'][i % 3],
  severity: 'low',
  src_ip: `192.168.1.${(i % 254) + 1}`,
  user: `user${i % 20}`
}));

// ─── Pulse (brief 7) — 8 detections, returned when rate limit allows ────────
const pulseDetections = Array.from({ length: 8 }, (_, i) => ({
  id: `d-pulse-${String(i + 1).padStart(3, '0')}`,
  time: `2026-05-30T12:${String(i * 5).padStart(2, '0')}:56Z`,
  severity: ['medium', 'high'][i % 2],
  tactic: ['credential_access', 'discovery', 'persistence'][i % 3],
  host: `endpoint-${i + 1}`
}));

// ─── Helix (brief 8) — 10 alerts, 5/page; assets ending '00' return 404 ─────
// Asset ID `i-000600` will 404; others will succeed. Pattern is deterministic
// so tests can assert on it.
const helixAlerts = Array.from({ length: 10 }, (_, i) => {
  const baseId = String(i + 1).padStart(4, '0');
  // Make the 6th alert's asset deliberately point at a non-existent asset (ends in '00')
  const assetTail = (i === 5) ? '00' : '';
  return {
    id: `alert-${String(9000 + i + 1).padStart(4, '0')}`,
    timestamp: `2026-05-30T12:${String(i * 5).padStart(2, '0')}:56Z`,
    severity: ['medium', 'high', 'critical'][i % 3],
    type: 'malware_detected',
    asset_id: `i-${baseId}${assetTail}`,
    indicator: `sha256:${'a'.repeat(40)}${i}`
  };
});

// ─── CCS v4 secret blobs per integration name ────────────────────────────────
// Atlas hits a real CCS v4 endpoint in prod. This is here for:
//   (a) documenting what each vendor's secret blob should look like
//   (b) local execution / light-executor scenarios where we replace CCS
// `instance_url` etc. point at this same mock service so generated templates
// route back here.
function base(suffix) {
  const root = process.env.PUBLIC_BASE_URL || 'http://localhost:3000';
  return `${root}${suffix}`;
}

const ccsSecrets = {
  VANILLA_BEARER: {
    instance_url: base('/vanilla-bearer'),
    api_token:    'mock-vanilla-bearer-token-abc123'
  },
  COBALT: {
    console_url:  base('/cobalt'),
    api_token:    'mock-cobalt-token-xyz789'
  },
  VORTEX: {
    api_url:       base('/vortex'),
    auth_url:      base('/vortex'),
    client_id:     'mock-vortex-client',
    client_secret: 'mock-vortex-secret'
  },
  NIMBUS: {
    instance_url: base('/nimbus'),
    api_token:    'mock-nimbus-apikey-123'
  },
  AEGIS: {
    instance_url: base('/aegis'),
    api_token:    'mock-aegis-key-321'
  },
  BASTION: {
    instance_url: base('/bastion'),
    username:     'mock-admin',
    password:     'mock-password'
  },
  PULSE: {
    instance_url: base('/pulse'),
    api_token:    'mock-pulse-key-654'
  },
  HELIX: {
    instance_url: base('/helix'),
    api_token:    'mock-helix-token-987'
  },

  // ─── WRITEBACK vendors (close-alert / response-action targets) ─────────────
  // These back the /sentinelshield, /nimbusguard, /threatnexus, /lumen writeback
  // routes. Field names mirror what the write-backs skill's generated handlers
  // read from .out.handler.http.http_get_sensor_secret_v4.data.<INTEGRATION_NAME>.
  SENTINELSHIELD_EDR: {              // archetype A — static API key, single call
    base_url: base('/sentinelshield'),
    api_key:  'mock-sentinelshield-key-aaa111'
  },
  NIMBUSGUARD_CLOUD: {               // archetype B — OAuth2 client_credentials
    base_url:      base('/nimbusguard'),
    client_id:     'mock-nimbusguard-client',
    client_secret: 'mock-nimbusguard-secret'
  },
  THREATNEXUS_XDR: {                 // archetype C — ApiToken, multi-step close + note
    base_url:   base('/threatnexus'),
    api_token:  'mock-threatnexus-token-ccc333',
    account_id: 'act-889900'
  },
  LUMEN_CNAPP: {                     // archetype D — OAuth2 + GraphQL mutation
    graphql_endpoint: base('/lumen/graphql'),
    auth_url:         base('/lumen'),
    client_id:        'mock-lumen-client',
    client_secret:    'mock-lumen-secret'
  }
};

module.exports = {
  vanillaBearerAlerts,
  cobaltDetections,
  vortexThreats,
  nimbusEvents,
  aegisAlertIds,
  aegisAlertDetail,
  bastionEvents,
  pulseDetections,
  helixAlerts,
  ccsSecrets
};
