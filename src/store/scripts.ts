const DECAY = `
local function decayed(value, last, tau, now)
  value = tonumber(value)
  last = tonumber(last)
  if not value or not last then return 0 end
  local elapsed = now - last
  if elapsed <= 0 then return value end
  return value * math.exp(-elapsed / tau)
end
local function keep_alive(key, ttl)
  if redis.call('PTTL', key) < ttl then redis.call('PEXPIRE', key, math.floor(ttl)) end
end
`;

export const OBSERVE_VISITOR = `${DECAY}
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local kind = ARGV[3]
local sid = ARGV[4]
local idle = tonumber(ARGV[5])
local click = ARGV[6]
local attribution = ARGV[7]
local request_tau = tonumber(ARGV[8])
local action_tau = tonumber(ARGV[9])
local conversion_tau = tonumber(ARGV[10])
local strike_tau = tonumber(ARGV[11])
local short_ttl = tonumber(ARGV[12])
local long_ttl = tonumber(ARGV[13])
local max_gap = tonumber(ARGV[14])
local alpha = tonumber(ARGV[15])

local f = redis.call('HMGET', KEYS[1], 'rv', 'rt', 'av', 'at', 'cv', 'ct', 'gl', 'gn', 'gm', 'gs',
  'sid', 'ss', 'sl', 'sd', 'sn', 'js', 'ix', 'af', 'cl', 'ru', 'kv', 'kt', 'co', 'pa')

local counted = kind ~= 'internal'
local rv = decayed(f[1], f[2], request_tau, now)
if counted then rv = rv + 1 end
local av = decayed(f[3], f[4], action_tau, now)
if kind == 'action' then av = av + 1 end
local cv = decayed(f[5], f[6], conversion_tau, now)
if kind == 'conversion' then cv = cv + 1 end

local gl = tonumber(f[7])
local gn = tonumber(f[8]) or 0
local gm = tonumber(f[9]) or 0
local gs = tonumber(f[10]) or 0
if kind == 'page' then
  if gl then
    local gap = now - gl
    if gap > 0 and gap < max_gap then
      if gn == 0 then
        gm = gap
        gs = 0
      else
        local d = gap - gm
        gm = gm + alpha * d
        gs = (1 - alpha) * (gs + alpha * d * d)
      end
      gn = math.min(gn + 1, 1000)
    end
  end
  gl = now
end

local ss = tonumber(f[12])
local sl = tonumber(f[13])
local sd = tonumber(f[14]) or 0
local sn = tonumber(f[15]) or 0
if f[11] ~= sid or not sl or not ss or now - sl > idle then
  ss = now
  sd = 0
  sn = sn + 1
end
if kind == 'page' then sd = sd + 1 end

local paid_short = 0
local paid_long = 0
if click ~= '' then
  redis.call('PFADD', KEYS[2], click)
  redis.call('PEXPIRE', KEYS[2], short_ttl)
  redis.call('PFADD', KEYS[4], click)
  redis.call('PEXPIRE', KEYS[4], long_ttl)
  paid_short = redis.call('PFCOUNT', KEYS[2], KEYS[3])
  paid_long = redis.call('PFCOUNT', KEYS[4], KEYS[5])
end

local fields = { 'rv', rv, 'rt', now, 'av', av, 'at', now, 'cv', cv, 'ct', now, 'gn', gn, 'gm', gm, 'gs', gs,
  'sid', sid, 'ss', ss, 'sl', now, 'sd', sd, 'sn', sn }
if gl then
  fields[#fields + 1] = 'gl'
  fields[#fields + 1] = gl
end
local pa = f[24]
if attribution ~= '' then
  pa = attribution
  fields[#fields + 1] = 'pa'
  fields[#fields + 1] = attribution
end
redis.call('HSET', KEYS[1], unpack(fields))

local hold = ttl
local cl = tonumber(f[19])
local ru = tonumber(f[20])
if ru and ru - now > hold then hold = ru - now end
if cl and cl - now > hold then hold = cl - now end
keep_alive(KEYS[1], hold)

return { tostring(rv), tostring(av), tostring(cv), tostring(gn), tostring(gm), tostring(gs), tostring(ss), tostring(sd),
  tostring(sn), f[16] or '', f[17] or '', f[18] or '', f[19] or '', f[20] or '',
  tostring(decayed(f[21], f[22], strike_tau, now)), f[23] or '', tostring(paid_short), tostring(paid_long), pa or '' }
`;

export const OBSERVE_ADDRESS = `${DECAY}
local now = tonumber(ARGV[1])
local request_tau = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local member = ARGV[4]
local population_ttl = tonumber(ARGV[5])
local strike_tau = tonumber(ARGV[6])

local f = redis.call('HMGET', KEYS[1], 'rv', 'rt', 'ru', 'kv', 'kt')
local rv = decayed(f[1], f[2], request_tau, now) + 1
redis.call('HSET', KEYS[1], 'rv', rv, 'rt', now)
local hold = ttl
local ru = tonumber(f[3])
if ru and ru - now > hold then hold = ru - now end
keep_alive(KEYS[1], hold)

if member ~= '' then
  redis.call('PFADD', KEYS[2], member)
  redis.call('PEXPIRE', KEYS[2], population_ttl)
end
local population = redis.call('PFCOUNT', KEYS[2], KEYS[3])
return { tostring(rv), tostring(population), f[3] or '', tostring(decayed(f[4], f[5], strike_tau, now)) }
`;

export const OBSERVE_NETWORK = `${DECAY}
local now = tonumber(ARGV[1])
local request_tau = tonumber(ARGV[2])
local conversion_tau = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local kind = ARGV[5]
local click = ARGV[6]
local fresh = ARGV[7]
local established = ARGV[8]
local short_ttl = tonumber(ARGV[9])
local long_ttl = tonumber(ARGV[10])
local fresh_ttl = tonumber(ARGV[11])
local population_ttl = tonumber(ARGV[12])

local f = redis.call('HMGET', KEYS[1], 'rv', 'rt', 'cv', 'ct')
local rv = decayed(f[1], f[2], request_tau, now) + 1
local cv = decayed(f[3], f[4], conversion_tau, now)
if kind == 'conversion' then cv = cv + 1 end
redis.call('HSET', KEYS[1], 'rv', rv, 'rt', now, 'cv', cv, 'ct', now)
redis.call('PEXPIRE', KEYS[1], ttl)

if click ~= '' then
  redis.call('PFADD', KEYS[2], click)
  redis.call('PEXPIRE', KEYS[2], short_ttl)
  redis.call('PFADD', KEYS[4], click)
  redis.call('PEXPIRE', KEYS[4], long_ttl)
end
if fresh ~= '' then
  redis.call('PFADD', KEYS[6], fresh)
  redis.call('PEXPIRE', KEYS[6], fresh_ttl)
end
if established ~= '' then
  redis.call('PFADD', KEYS[8], established)
  redis.call('PEXPIRE', KEYS[8], population_ttl)
end

return { tostring(rv), tostring(cv), tostring(redis.call('PFCOUNT', KEYS[2], KEYS[3])),
  tostring(redis.call('PFCOUNT', KEYS[4], KEYS[5])), tostring(redis.call('PFCOUNT', KEYS[6], KEYS[7])),
  tostring(redis.call('PFCOUNT', KEYS[8], KEYS[9])) }
`;

export const OBSERVE_DISTINCT = `
redis.call('PFADD', KEYS[1], ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return redis.call('PFCOUNT', KEYS[1], KEYS[2])
`;

export const RESTRICT = `${DECAY}
local until_ms = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local strike_tau = tonumber(ARGV[4])
local f = redis.call('HMGET', KEYS[1], 'ru', 'kv', 'kt')
local ru = math.max(tonumber(f[1]) or 0, until_ms)
local kv = decayed(f[2], f[3], strike_tau, now) + 1
redis.call('HSET', KEYS[1], 'ru', ru, 'kv', kv, 'kt', now)
keep_alive(KEYS[1], math.max(ttl, ru - now))
return tostring(kv)
`;

export const PATCH = `${DECAY}
local ttl = tonumber(ARGV[1])
if #ARGV > 2 then
  local values = {}
  for i = 3, #ARGV do values[#values + 1] = ARGV[i] end
  redis.call('HSET', KEYS[1], unpack(values))
end
if ARGV[2] ~= '' then redis.call('HINCRBY', KEYS[1], ARGV[2], 1) end
keep_alive(KEYS[1], ttl)
return 1
`;

export const COUNTER = `${DECAY}
local now = tonumber(ARGV[1])
local tau = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local f = redis.call('HMGET', KEYS[1], 'v', 't')
local value = decayed(f[1], f[2], tau, now) + 1
redis.call('HSET', KEYS[1], 'v', value, 't', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return tostring(value)
`;
