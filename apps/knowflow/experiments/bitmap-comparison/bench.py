"""Isolated Redis bitmap comparison. Python standard library only."""
import argparse, json, math, os, platform, random, socket, statistics, subprocess, tempfile, time
from pathlib import Path

class Redis:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)
        self.f = self.sock.makefile('rb')
    def read(self):
        line = self.f.readline()
        if not line: raise EOFError('Redis disconnected')
        kind, body = line[:1], line[1:-2]
        if kind == b'-': raise RuntimeError(body.decode())
        if kind == b':': return int(body)
        if kind == b'+': return body.decode()
        if kind == b'$':
            n = int(body)
            if n == -1: return None
            value = self.f.read(n); self.f.read(2); return value
        if kind == b'*': return [self.read() for _ in range(int(body))]
        raise ValueError(line)
    def batch(self, commands):
        data = bytearray()
        for command in commands:
            data.extend(f'*{len(command)}\r\n'.encode())
            for arg in command:
                arg = str(arg).encode()
                data.extend(f'${len(arg)}\r\n'.encode() + arg + b'\r\n')
        self.sock.sendall(data)
        return [self.read() for _ in commands]
    def cmd(self, *args): return self.batch([args])[0]
    def close(self): self.f.close(); self.sock.close()

def locate(mode, uid):
    if mode.endswith('sharded'): return f'bm:like:knowpost:123:{uid // 32768}', uid % 32768
    return 'bm:like:knowpost:123', uid

def commands(mode):
    prefix = '' if mode == 'native-sharded' else ('R64.' if mode == 'roaring64-single' else 'R.')
    return prefix + 'GETBIT', prefix + 'SETBIT', prefix + 'BITCOUNT'

def info(r):
    return {k: v for line in r.cmd('INFO', 'memory').decode().splitlines() if ':' in line for k,v in [line.split(':', 1)]}

def quantiles(samples):
    ordered = sorted(samples)
    return {f'p{p}_us': round(ordered[min(len(ordered)-1, math.ceil(len(ordered)*p/100)-1)], 2) for p in (50,95,99)}

def run(r, mode, ids, repeats):
    r.cmd('FLUSHDB')  # Only the temporary server created by this script.
    get, setbit, count = commands(mode)
    script = f"local old=redis.call('{get}',KEYS[1],ARGV[1]); if old==tonumber(ARGV[2]) then return 0 end; redis.call('{setbit}',KEYS[1],ARGV[1],ARGV[2]); return 1"
    sha = r.cmd('SCRIPT', 'LOAD', script).decode()
    # Prime command/Lua bookkeeping before measuring dataset allocation.
    warm_key = 'benchmark:warmup'
    for _ in range(3):
        r.batch([('EVALSHA', sha, 1, warm_key, 0, i % 2) for i in range(256)])
    r.cmd('DEL', warm_key)
    info(r)
    time.sleep(0.5)  # Let serverCron settle client accounting/buffer reclamation.
    before_info = info(r)
    before = int(before_info['used_memory']) - int(before_info['mem_clients_normal'])
    keys = set()
    start = time.perf_counter()
    for i in range(0, len(ids), 256):
        batch = []
        for uid in ids[i:i+256]:
            key, offset = locate(mode, uid); keys.add(key)
            batch.append(('EVALSHA', sha, 1, key, offset, 1))
        assert all(x == 1 for x in r.batch(batch))
    load_s = time.perf_counter()-start
    time.sleep(0.5)
    after_info = info(r)
    allocated = int(after_info['used_memory']) - int(after_info['mem_clients_normal']) - before
    key_memory = sum(r.cmd('MEMORY', 'USAGE', key) for key in keys)
    # Exact cardinality plus every inserted member, and known absent members.
    assert sum(r.cmd(count, key) for key in keys) == len(ids)
    for i in range(0, len(ids), 256):
        assert all(x == 1 for x in r.batch([(get, *locate(mode, uid)) for uid in ids[i:i+256]]))
    seen = set(ids); absent = [uid+1 for uid in ids[:500] if uid+1 not in seen]
    assert all(x == 0 for x in r.batch([(get, *locate(mode, uid)) for uid in absent]))
    # Warm up, then measure non-pipelined round trips including Python/client overhead.
    sample = random.Random(42).choices(ids, k=2000)
    for uid in sample[:200]: r.cmd(get, *locate(mode, uid))
    reads, writes = [], []
    for _ in range(repeats):
        read_times, write_times = [], []
        for uid in sample:
            key, offset = locate(mode, uid)
            start = time.perf_counter_ns(); value = r.cmd(get, key, offset)
            read_times.append((time.perf_counter_ns()-start)/1000); assert value == 1
        for uid in sample:
            key, offset = locate(mode, uid)
            for state in (0, 0, 1, 1):
                start = time.perf_counter_ns(); changed = r.cmd('EVALSHA', sha, 1, key, offset, state)
                write_times.append((time.perf_counter_ns()-start)/1000)
                assert changed == (1 if len(write_times)%2 else 0)
        reads.append(quantiles(read_times)); writes.append(quantiles(write_times))
    assert sum(r.cmd(count, key) for key in keys) == len(ids)
    return dict(mode=mode, keys=len(keys), members=len(ids), key_memory_bytes=key_memory,
                used_memory_delta_bytes=allocated, memory_before=before_info, memory_after=after_info, load_seconds=round(load_s,3),
                read_rounds=reads, toggle_rounds=writes, correctness='passed')

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--module', required=True); ap.add_argument('--redis-server', default='redis-server'); ap.add_argument('--output', default='results.json'); ap.add_argument('--repeats', type=int, default=3)
    args = ap.parse_args(); rng = random.Random(20260928)
    cases = {'dense': list(range(60000)), 'sparse_32': rng.sample(range(1_000_000_000),10000),
             'clustered': [c*1_000_000+i for c in range(100) for i in range(100)],
             'sparse_64': [(1<<55)+x for x in rng.sample(range(1_000_000_000),10000)]}
    result = dict(platform=platform.platform(), python=platform.python_version(),
        redis=subprocess.check_output([args.redis_server,'--version'],text=True).strip(), module=os.path.abspath(args.module), repeats=args.repeats, cases={})
    # Each variant gets a fresh process: no cross-variant allocator/script-cache history.
    for name, ids in cases.items():
        result['cases'][name] = []
        modes = ['native-sharded','roaring-sharded','roaring64-single']
        if name != 'sparse_64': modes.insert(2,'roaring-single')
        for mode in modes:
            with tempfile.TemporaryDirectory(prefix='kf-bm-') as tmp:
                sock = tmp+'/redis.sock'
                with open(tmp+'/redis.log','w+') as log:
                    proc = subprocess.Popen([args.redis_server,'--port','0','--unixsocket',sock,'--save','','--appendonly','no','--loadmodule',os.path.abspath(args.module),'--dir',tmp],stdout=log,stderr=log)
                    r = None
                    try:
                        for _ in range(100):
                            if proc.poll() is not None:
                                log.seek(0); raise RuntimeError(log.read())
                            try: r=Redis(sock); break
                            except (FileNotFoundError,ConnectionRefusedError): time.sleep(.05)
                        if r is None: raise TimeoutError('Redis startup')
                        item=run(r,mode,ids,args.repeats); result['cases'][name].append(item)
                        print(name,mode,'memory=',item['key_memory_bytes'],'read=',item['read_rounds'],flush=True)
                    finally:
                        if r: r.close()
                        proc.terminate(); proc.wait(timeout=10)
            Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
if __name__ == '__main__': main()
