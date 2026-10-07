#!/usr/bin/env python3
"""Offline native -> Roaring shard migration. Never run with active writers."""
import argparse
import json
import os
import re
import socket

class Redis:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=30)
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

MODE_KEY = 'counter:bitmap:storage-mode'

def scan(r, pattern):
    cursor = 0
    keys = set()
    while True:
        cursor, batch = r.cmd('SCAN', cursor, 'MATCH', pattern, 'COUNT', 256)
        keys.update(k.decode() for k in batch)
        if int(cursor) == 0: return keys

def members(raw):
    return [i * 8 + bit for i, byte in enumerate(raw) for bit in range(8)
            if byte & (1 << (7 - bit))]

def migrate(r, apply=False, writers_stopped=False):
    if apply and not writers_stopped:
        raise ValueError('--apply requires --writers-stopped; stop every application writer first')
    marker = r.cmd('GET', MODE_KEY)
    if marker == b'roaring':
        raise ValueError('Already activated; refusing to overwrite potentially newer Roaring data')
    if marker not in (None, b'migrating'):
        raise ValueError('Unknown migration marker')
    for command in ('R.GETBIT', 'R.SETBIT', 'R.BITCOUNT', 'R.SETINTARRAY', 'R.GETINTARRAY'):
        if not r.cmd('COMMAND', 'INFO', command)[0]:
            raise ValueError('Missing module command: ' + command)
    source = scan(r, 'bm:*')
    snapshots = {}
    for key in sorted(source):
        if not re.fullmatch(r'bm:(like|fav):[^:*?\[\]{}]+:[^:*?\[\]{}]+:[0-9]+', key):
            raise ValueError('Unexpected bitmap key: ' + key)
        raw = r.cmd('GET', key)
        if raw is None or len(raw) > 4096 or r.cmd('PTTL', key) != -1:
            raise ValueError('Source must be a persistent shard of at most 4096 bytes: ' + key)
        snapshots[key] = raw
    targets = {'r' + key for key in source}
    if scan(r, 'rbm:*') - targets:
        raise ValueError('Unrelated Roaring keys exist; refusing mixed datasets')
    summary = {'shards': len(source), 'members': sum(len(members(v)) for v in snapshots.values()), 'apply': apply}
    if not apply: return summary
    r.cmd('SET', MODE_KEY, 'migrating')
    for key, raw in snapshots.items():
        target = 'r' + key
        ids = members(raw)
        if r.cmd('EXISTS', target):
            if r.cmd('R.GETINTARRAY', target) != ids:
                raise ValueError('Existing target mismatch: ' + target)
        elif ids:
            r.cmd('R.SETINTARRAY', target, *ids)
        actual = r.cmd('R.GETINTARRAY', target) if r.cmd('EXISTS', target) else []
        if actual != ids or r.cmd('R.BITCOUNT', target) != len(ids):
            raise ValueError('Verification failed: ' + target)
    if scan(r, 'bm:*') != source or any(r.cmd('GET', k) != v for k,v in snapshots.items()):
        raise ValueError('Source changed during migration; keep application stopped')
    r.cmd('SET', MODE_KEY, 'roaring')
    return summary

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--host', default='127.0.0.1'); ap.add_argument('--port', type=int, default=6379)
    ap.add_argument('--db', type=int, default=0)
    ap.add_argument('--apply', action='store_true'); ap.add_argument('--writers-stopped', action='store_true')
    args = ap.parse_args(); r = Redis(args.host, args.port)
    try:
        password = os.environ.get('REDIS_PASSWORD')
        if password:
            user = os.environ.get('REDIS_USERNAME')
            r.cmd('AUTH', *([user,password] if user else [password]))
        r.cmd('SELECT', args.db)
        print(json.dumps(migrate(r, args.apply, args.writers_stopped)))
    finally: r.close()
if __name__ == '__main__': main()
