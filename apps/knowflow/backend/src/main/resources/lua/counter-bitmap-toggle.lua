-- Commands are supplied by BitmapStore's validated native/roaring strategy.
-- All operations touch one shard; compare and update execute atomically.
local previous = redis.call(ARGV[1], KEYS[1], ARGV[3])
local desired = tonumber(ARGV[4])
if previous == desired then return 0 end
redis.call(ARGV[2], KEYS[1], ARGV[3], desired)
return 1
