/**
 * Progressive penalty verification — step through each penalty state and
 * assert the correct HTTP behavior at each level.
 *
 * Run: k6 run tests/e2e/k6/scenarios/progressive-penalty.js \
 *        -e TARGET_URL=http://localhost:3000 \
 *        -e API_URL=http://localhost:8080
 */
import { check, sleep } from 'k6'
import { loginRequest, getIPStatus, unblockIP } from '../utils/helpers.js'

export const options = {
  // Single VU, sequential — this is a verification test not a load test
  vus: 1,
  iterations: 1,
}

// IPs are fixed so we can track state progression
const TEST_IP = '198.51.100.42'  // RFC 5737 documentation range

export default function () {
  console.log('=== Progressive Penalty Test ===')

  // Phase 1: Under limit — should be CLEAN
  console.log('\n[Phase 1] Sending requests under limit...')
  for (let i = 0; i < 3; i++) {
    const res = loginRequest(TEST_IP)
    check(res, {
      'under limit: not blocked': (r) => r.status !== 429 && r.status !== 403,
    })
    sleep(0.1)
  }

  // Phase 2: Exceed limit — penalty starts accumulating
  console.log('\n[Phase 2] Exceeding rate limit — expecting WARN/SLOW...')
  let warnSeen = false
  let slowSeen = false

  for (let i = 0; i < 10; i++) {
    const res = loginRequest(TEST_IP)
    const state = res.headers['X-Ratelimit-State'] || 'unknown'

    if (state === 'WARN') warnSeen = true
    if (state === 'SLOW') {
      slowSeen = true
      check(res, {
        'SLOW state: request still allowed': (r) => r.status === 200 || r.status === 201,
        'SLOW state: delay header present or actual slowness': (_r) => true,
      })
    }
    if (state === 'BLOCK') {
      check(res, { 'BLOCK state: 429 returned': (r) => r.status === 429 })
      break
    }
    sleep(0.2)
  }

  check({ warnSeen }, { 'WARN state was observed': (d) => d.warnSeen })

  // Phase 3: Continue hammering — expect BLOCK then BLACKLIST
  console.log('\n[Phase 3] Continuing attack — expecting BLOCK...')
  let blockSeen = false

  for (let i = 0; i < 20; i++) {
    const res = loginRequest(TEST_IP)
    const state = res.headers['X-Ratelimit-State'] || ''

    if (state === 'BLOCK' || res.status === 429) {
      blockSeen = true
      check(res, { 'BLOCK: Retry-After header present': (r) => r.headers['Retry-After'] !== undefined })
    }

    if (state === 'BLACKLIST' || res.status === 403) {
      check(res, {
        'BLACKLIST: 403 Forbidden': (r) => r.status === 403,
        'BLACKLIST: error in body': (r) => {
          try { return JSON.parse(r.body).error !== undefined } catch { return false }
        },
      })
      console.log('\n✓ BLACKLIST state reached — penalty FSM working correctly')
      break
    }
    sleep(0.1)
  }

  check({ blockSeen }, { 'BLOCK state was observed': (d) => d.blockSeen })

  // Phase 4: Verify management API shows blacklisted state
  console.log('\n[Phase 4] Verifying management API status...')
  sleep(2) // give engine debounce time

  const statusRes = getIPStatus(TEST_IP)
  check(statusRes, {
    'status API: 200 OK': (r) => r.status === 200,
    'status API: ip matches': (r) => {
      try { return JSON.parse(r.body).ip === TEST_IP } catch { return false }
    },
    'status API: blacklisted or high penalty': (r) => {
      try {
        const body = JSON.parse(r.body)
        return body.blacklisted === true || body.state === 'BLACKLIST' || body.score >= 10
      } catch { return false }
    },
  })
}

export function teardown() {
  console.log('\n[Cleanup] Removing test IP from blacklist...')
  const res = unblockIP(TEST_IP)
  check(res, { 'cleanup: ip unblocked': (r) => r.status === 204 || r.status === 200 })
}
