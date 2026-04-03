/**
 * Full load test — combines all scenarios for a comprehensive soak test.
 *
 * Run: k6 run tests/e2e/k6/load-test.js \
 *        -e TARGET_URL=http://localhost:3000 \
 *        -e API_URL=http://localhost:8080 \
 *        -e API_KEY=changeme-admin
 *
 * Output summary metrics to stdout (add --out json=results.json for file output).
 */
import { check, sleep } from 'k6'
import { Rate, Counter, Trend } from 'k6/metrics'
import { loginRequest, productsRequest, randomIP } from './utils/helpers.js'

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // 1. Steady legitimate traffic
    legitimate: {
      executor: 'constant-arrival-rate',
      rate: 20,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 30,
      maxVUs: 100,
      tags: { scenario: 'legitimate' },
    },

    // 2. Single-IP brute force (starts at 1m)
    brute_force: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      startTime: '1m',
      duration: '2m',
      preAllocatedVUs: 5,
      maxVUs: 10,
      tags: { scenario: 'brute_force' },
    },

    // 3. Distributed low-and-slow (many IPs, slow rate — tests multi-dimensional)
    distributed: {
      executor: 'ramping-arrival-rate',
      startRate: 5,
      timeUnit: '1s',
      preAllocatedVUs: 20,
      maxVUs: 50,
      stages: [
        { duration: '2m', target: 30 },
        { duration: '1m', target: 100 },
        { duration: '2m', target: 30 },
      ],
      startTime: '2m',
      tags: { scenario: 'distributed' },
    },
  },

  thresholds: {
    // SLOs
    'http_req_duration{scenario:legitimate}': ['p(95)<500', 'p(99)<2000'],
    'http_req_failed{scenario:legitimate}': ['rate<0.01'],

    // Attackers must be stopped
    'requests_blocked{scenario:brute_force}': ['count>20'],

    // Legitimate users not impacted during attack
    'false_positive_rate': ['rate<0.02'],

    // Overall availability
    http_req_failed: ['rate<0.05'],
  },
}

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const falsePositiveRate = new Rate('false_positive_rate')
const requestsBlocked = new Counter('requests_blocked')
const penaltyLatency = new Trend('penalty_latency')

// Simulated attacker uses a fixed IP
const ATTACKER_IP = '203.0.113.77'

// ---------------------------------------------------------------------------
// Main scenario function
// ---------------------------------------------------------------------------

export default function () {
  const scenario = __ENV.SCENARIO || 'legitimate'
  const isBruteForce = scenario === 'brute_force'
  const ip = isBruteForce ? ATTACKER_IP : randomIP(`10.${__VU % 10}`)

  const start = Date.now()
  const res = loginRequest(ip, {
    username: isBruteForce ? 'admin' : `user-${__VU}`,
    password: isBruteForce ? 'guessing' : 'correct-pass',
  })
  penaltyLatency.add(Date.now() - start)

  const blocked = res.status === 429 || res.status === 403
  requestsBlocked.add(blocked ? 1 : 0)

  if (!isBruteForce) {
    // Legitimate users should not be blocked
    falsePositiveRate.add(blocked ? 1 : 0)
    check(res, {
      'legitimate: not rate-limited': (r) => r.status !== 429 && r.status !== 403,
      'legitimate: response time OK': (r) => r.timings.duration < 2000,
    })
  }

  sleep(isBruteForce ? 0 : Math.random() * 1.5 + 0.5)
}

// ---------------------------------------------------------------------------
// Summary output
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    duration: data.state.testRunDurationMs / 1000,
    thresholds_passed: Object.values(data.metrics)
      .filter(m => m.thresholds)
      .every(m => Object.values(m.thresholds).every(t => !t.ok === false)),
    key_metrics: {
      p95_login_ms: data.metrics['http_req_duration{scenario:legitimate}']?.values?.['p(95)'] ?? 'N/A',
      false_positive_rate: data.metrics['false_positive_rate']?.values?.rate ?? 0,
      requests_blocked: data.metrics['requests_blocked']?.values?.count ?? 0,
      error_rate: data.metrics['http_req_failed']?.values?.rate ?? 0,
    },
  }

  console.log('\n=== AutoBlock Load Test Summary ===')
  console.log(JSON.stringify(summary, null, 2))

  return {
    stdout: JSON.stringify(summary, null, 2),
  }
}
