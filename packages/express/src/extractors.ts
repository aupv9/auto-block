import type { Request } from 'express'

// ---------------------------------------------------------------------------
// IP extraction
// ---------------------------------------------------------------------------

/**
 * Extract the real client IP from a request.
 *
 * Priority:
 *   1. X-Forwarded-For (leftmost, i.e. original client) when trustProxy=true
 *   2. X-Real-IP when trustProxy=true
 *   3. socket.remoteAddress (direct connection)
 */
export function extractIP(req: Request, options: { trustProxy?: boolean; depth?: number } = {}): string {
  const { trustProxy = true, depth = 1 } = options

  if (trustProxy) {
    const xff = req.headers['x-forwarded-for']
    if (xff) {
      const ips = (Array.isArray(xff) ? xff[0] : xff).split(',').map(s => s.trim())
      // depth=1 → leftmost is the real client (single proxy in front)
      const ip = ips[ips.length - depth] ?? ips[0]
      if (ip) return normalizeIP(ip)
    }

    const realIP = req.headers['x-real-ip']
    if (realIP) {
      return normalizeIP(Array.isArray(realIP) ? realIP[0]! : realIP)
    }
  }

  return normalizeIP(req.socket.remoteAddress ?? '127.0.0.1')
}

/** Strip IPv6 ::ffff: prefix so IPv4-mapped addresses compare cleanly */
function normalizeIP(ip: string): string {
  return ip.replace(/^::ffff:/, '')
}

// ---------------------------------------------------------------------------
// User ID extraction
// ---------------------------------------------------------------------------

export type UserIdExtractor = (req: Request) => string | undefined

/**
 * Decode JWT payload (no verification — only for rate limiting, not auth).
 * Returns `sub` claim if present, undefined otherwise.
 */
export function jwtSubExtractor(req: Request): string | undefined {
  const auth = req.headers.authorization
  if (!auth?.startsWith('Bearer ')) return undefined

  const token = auth.slice(7)
  const parts = token.split('.')
  if (parts.length !== 3) return undefined

  try {
    const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8')) as unknown
    if (typeof payload === 'object' && payload !== null && 'sub' in payload) {
      const sub = (payload as Record<string, unknown>)['sub']
      return typeof sub === 'string' ? sub : undefined
    }
  } catch {
    // malformed JWT — not an error, just return undefined
  }
  return undefined
}

/**
 * Extract user ID from a custom header (e.g. X-User-ID set by upstream auth proxy).
 */
export function headerExtractor(headerName: string): UserIdExtractor {
  return (req: Request) => {
    const val = req.headers[headerName.toLowerCase()]
    if (!val) return undefined
    return Array.isArray(val) ? val[0] : val
  }
}

/** Build the configured extractor from middleware options */
export function buildUserIdExtractor(options: {
  userIdExtractor?: 'jwt_sub' | 'header' | 'none'
  userIdHeader?: string
}): UserIdExtractor {
  if (options.userIdExtractor === 'jwt_sub') return jwtSubExtractor
  if (options.userIdExtractor === 'header' && options.userIdHeader) {
    return headerExtractor(options.userIdHeader)
  }
  return () => undefined
}
