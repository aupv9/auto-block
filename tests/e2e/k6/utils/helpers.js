import http from 'k6/http'
import { check, sleep } from 'k6'

const BASE_URL = __ENV.TARGET_URL || 'http://localhost:3000'
const API_URL = __ENV.API_URL || 'http://localhost:8080'
const API_KEY = __ENV.API_KEY || 'changeme-admin'

/** Make a POST request to the target login endpoint. */
export function loginRequest(ip, body = { username: 'test', password: 'wrong' }) {
  return http.post(`${BASE_URL}/api/auth/login`, JSON.stringify(body), {
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-For': ip,
    },
    tags: { endpoint: 'login' },
  })
}

/** Make a GET request to the target products endpoint. */
export function productsRequest(ip) {
  return http.get(`${BASE_URL}/api/products`, {
    headers: { 'X-Forwarded-For': ip },
    tags: { endpoint: 'products' },
  })
}

/** Query the AutoBlock management API for an IP's current status. */
export function getIPStatus(ip) {
  return http.get(`${API_URL}/api/v1/status/ip/${ip}`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  })
}

/** Manually whitelist an IP via the management API. */
export function whitelistIP(ip) {
  return http.post(`${API_URL}/api/v1/whitelist/ip`, JSON.stringify({ ip }), {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`,
    },
  })
}

/** Manually remove an IP from the blacklist. */
export function unblockIP(ip) {
  return http.del(`${API_URL}/api/v1/blacklist/ip/${ip}`, null, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  })
}

/** Generate a fake IP in the given subnet. */
export function randomIP(subnet = '10.0') {
  const c = Math.floor(Math.random() * 254) + 1
  const d = Math.floor(Math.random() * 254) + 1
  return `${subnet}.${c}.${d}`
}

/** Assert the response has a specific state header. */
export function checkState(res, expectedState) {
  return check(res, {
    [`state is ${expectedState}`]: (r) => r.headers['X-Ratelimit-State'] === expectedState,
  })
}

export { BASE_URL, API_URL, API_KEY }
