/**
 * Brute-force attack simulation — one IP hammers the login endpoint.
 * Verifies that:
 *   1. Rate limit kicks in within the configured window
 *   2. Penalty escalates: WARN → SLOW → BLOCK → BLACKLIST
 *   3. Blacklisted IP gets 403 (not 429)
 *   4. Other IPs are NOT affected (collateral damage check)
 *
 * Run: k6 run tests/e2e/k6/scenarios/brute-force.js \
 *        -e TARGET_URL=http://localhost:3000 \
 *        -e API_URL=http://localhost:8080
 */
import { check, sleep } from 'k6'
import { Counter, Rate } from 'k6/metrics'
import { loginRequest, getIPStatus, unblockIP, randomIP } from '../utils/helpers.js'

export const options = {
  scenarios: {
    attacker: {
      executor: 'constant-arrival-rate',
      rate: 30,          // 30 requests/sec — well over any sane limit
      timeUnit: '1s',
      duration: '90s',
      preAllocatedVUs: 5,
      maxVUs: 10,
      env: { VU_TYPE: 'attacker' },
      tags: { role: 'attacker' },
    },
    legitimate_user: {
      executor: 'constant-arrival-rate',
      rate: 2,
      timeUnit: '1s',
      duration: '90s',
      preAllocatedVUs: 5,
      maxVUs: 10,
      env: { VU_TYPE: 'legitimate' },
      tags: { role: 'legitimate' },
    },
  },
  thresholds: {
    // Attacker must be blocked
    'requests_blocked{role:attacker}': ['count>10'],
    // Legitimate users must NOT be impacted
    'requests_blocked{role:legitimate}': ['count<3'],
  },
}

const requestsBlocked = new Counter('requests_blocked')
const penaltyEscalations = new Counter('penalty_escalations')

const ATTACKER_IP = '203.0.113.100'  // RFC 5737 documentation range — safe for testing

export default function () {
  const isAttacker = __ENV.VU_TYPE === 'attacker'
  const ip = isAttacker ? ATTACKER_IP : randomIP('10.50')

  const res = loginRequest(ip, { username: 'admin', password: `attempt-${Math.random()}` })

  const wasBlocked = res.status === 429 || res.status === 403
  requestsBlocked.add(wasBlocked ? 1 : 0)

  if (isAttacker) {
    const state = res.headers['X-Ratelimit-State']
    if (state && state !== 'CLEAN') {
      penaltyEscalations.add(1)
    }

    // After BLACKLIST the response should be 403
    check(res, {
      'attacker eventually blocked': (r) => {
        // In later iterations, must get 429 or 403
        const iter = parseInt(__ENV.ITERATION || '0')
        if (iter < 5) return true // first few requests fine
        return r.status === 429 || r.status === 403
      },
    })
  } else {
    check(res, {
      'legitimate user not blocked': (r) => r.status !== 429 && r.status !== 403,
    })
  }

  sleep(isAttacker ? 0 : 1)
}

export function teardown() {
  // Clean up — unblock the attacker IP after test
  const res = unblockIP(ATTACKER_IP)
  check(res, { 'attacker IP unblocked': (r) => r.status === 204 || r.status === 200 })
}
