import { describe, it, expect } from 'vitest'
import { KeyBuilder } from '../key-builder.js'

describe('KeyBuilder', () => {
  const kb = new KeyBuilder('acme')

  describe('endpointHash', () => {
    it('returns 8-char hex string', () => {
      const h = kb.endpointHash('/api/login')
      expect(h).toHaveLength(8)
      expect(h).toMatch(/^[0-9a-f]{8}$/)
    })

    it('is deterministic', () => {
      expect(kb.endpointHash('/api/login')).toBe(kb.endpointHash('/api/login'))
    })

    it('produces different hashes for different paths', () => {
      expect(kb.endpointHash('/api/login')).not.toBe(kb.endpointHash('/api/logout'))
    })
  })

  describe('slidingWindow', () => {
    it('builds key without epHash', () => {
      expect(kb.slidingWindow('ip', '1.2.3.4')).toBe('ab:acme:sw:ip:1.2.3.4')
    })

    it('builds key with epHash', () => {
      expect(kb.slidingWindow('ip', '1.2.3.4', 'a1b2c3d4')).toBe('ab:acme:sw:ip:1.2.3.4:a1b2c3d4')
    })
  })

  describe('tokenBucket', () => {
    it('builds correct key', () => {
      expect(kb.tokenBucket('uid', 'user123', 'a1b2c3d4')).toBe('ab:acme:tb:uid:user123:a1b2c3d4')
    })
  })

  describe('penalty keys', () => {
    it('penaltyScore includes dimension', () => {
      expect(kb.penaltyScore('ip', '1.2.3.4')).toBe('ab:acme:penalty:score:ip:1.2.3.4')
    })

    it('penaltyState includes dimension', () => {
      expect(kb.penaltyState('uid', 'user123')).toBe('ab:acme:penalty:state:uid:user123')
    })

    it('penaltyHistory includes dimension', () => {
      expect(kb.penaltyHistory('ip', '5.6.7.8')).toBe('ab:acme:penalty:history:ip:5.6.7.8')
    })
  })

  describe('blacklist / whitelist', () => {
    it('blacklist key', () => {
      expect(kb.blacklist('ip')).toBe('ab:acme:blacklist:ip')
    })

    it('whitelist key', () => {
      expect(kb.whitelist('uid')).toBe('ab:acme:whitelist:uid')
    })
  })

  describe('custom prefix', () => {
    it('respects custom prefix', () => {
      const custom = new KeyBuilder('tenant1', 'myapp')
      expect(custom.slidingWindow('ip', '1.2.3.4')).toBe('myapp:tenant1:sw:ip:1.2.3.4')
    })
  })
})
