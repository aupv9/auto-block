"""Lua scripts — identical logic to TypeScript redis-setup.ts.
All rate-limit counter operations MUST be atomic."""

SLIDING_WINDOW = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)

local count = redis.call('ZCARD', key)

if count >= limit then
  return {0, count, 0}
end

redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, window * 2)

return {1, count + 1, limit - count - 1}
"""

TOKEN_BUCKET = """
local key      = KEYS[1]
local now      = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local rate     = tonumber(ARGV[3])
local cost     = tonumber(ARGV[4])

local bucket      = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens      = tonumber(bucket[1]) or capacity
local last_refill = tonumber(bucket[2]) or now

local elapsed_sec = (now - last_refill) / 1000
local new_tokens  = math.min(capacity, tokens + (elapsed_sec * rate))
local expire_ms   = math.ceil(capacity / rate) * 2000

if new_tokens < cost then
  redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
  redis.call('PEXPIRE', key, expire_ms)
  return {0, math.floor(new_tokens)}
end

new_tokens = new_tokens - cost
redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
redis.call('PEXPIRE', key, expire_ms)

return {1, math.floor(new_tokens)}
"""

PENALTY_TRANSITION = """
local score_key   = KEYS[1]
local state_key   = KEYS[2]
local history_key = KEYS[3]

local incr        = tonumber(ARGV[1])
local t_warn      = tonumber(ARGV[2])
local t_slow      = tonumber(ARGV[3])
local t_block     = tonumber(ARGV[4])
local t_blacklist = tonumber(ARGV[5])
local ttl         = tonumber(ARGV[6])
local history_entry = ARGV[7]

local new_score = redis.call('INCRBY', score_key, incr)
redis.call('EXPIRE', score_key, ttl)

local state
if new_score >= t_blacklist then
  state = 'BLACKLIST'
elseif new_score >= t_block then
  state = 'BLOCK'
elseif new_score >= t_slow then
  state = 'SLOW'
elseif new_score >= t_warn then
  state = 'WARN'
else
  state = 'CLEAN'
end

local old_state = redis.call('GET', state_key) or 'CLEAN'
redis.call('SET', state_key, state, 'EX', ttl)

redis.call('LPUSH', history_key, history_entry)
redis.call('LTRIM', history_key, 0, 99)
if redis.call('TTL', history_key) < 0 then
  redis.call('EXPIRE', history_key, ttl)
end

return {new_score, state, old_state}
"""

BLACKLIST_CHECK = """
local key = KEYS[1]
local ip  = ARGV[1]
local now = tonumber(ARGV[2])

local score = redis.call('ZSCORE', key, ip)
if not score then return 0 end

score = tonumber(score)
if score == 0 then return 1 end
if score > now then return 1 end

redis.call('ZREM', key, ip)
return 0
"""
