/**
 * Baseline load test — normal traffic, verify no false positives.
 *
 * Run: k6 run tests/e2e/k6/scenarios/baseline.js
 */
import { check, sleep } from 'k6'
import { Rate, Trend } from 'k6/metrics'
import { loginRequest, productsRequest, randomIP } from '../utils/helpers.js'

export const options = {
  scenarios: {
    normal_login: {
      executor: 'constant-arrival-rate',
      rate: 10,              // 10 logins per second (well under typical limit)
      timeUnit: '1s',
      duration: '2m',
      preAllocatedVUs: 20,
      maxVUs: 50,
      tags: { scenario: 'normal_login' },
    },
    browse_products: {
      executor: 'ramping-vus',
      stages: [
        { duration: '30s', target: 20 },
        { duration: '1m', target: 50 },
        { duration: '30s', target: 0 },
      ],
      tags: { scenario: 'browse' },
    },
  },
  thresholds: {
    // No legitimate users should be blocked
    'http_req_failed{endpoint:login}': ['rate<0.01'],
    'http_req_failed{endpoint:products}': ['rate<0.01'],
    // p95 latency must stay under 500ms (SLOW state adds 3s delay — would breach this)
    'http_req_duration{endpoint:login}': ['p(95)<500'],
  },
}

const falsePositiveRate = new Rate('false_positives')

export default function () {
  // Each VU uses a unique IP to avoid triggering rate limits
  const ip = randomIP('172.16')

  const loginRes = loginRequest(ip, { username: `user-${__VU}`, password: 'correctpassword' })

  falsePositiveRate.add(loginRes.status === 429 || loginRes.status === 403)

  check(loginRes, {
    'login not rate-limited': (r) => r.status !== 429 && r.status !== 403,
    'login response under 500ms': (r) => r.timings.duration < 500,
  })

  sleep(1)

  const productsRes = productsRequest(ip)
  check(productsRes, {
    'products not rate-limited': (r) => r.status !== 429 && r.status !== 403,
  })

  sleep(Math.random() * 2)
}
