"""Real-module offline migration tests, using a private Redis Unix socket."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('migration', Path(__file__).with_name('migrate-bitmaps.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

@unittest.skipUnless(os.environ.get('ROARING_MODULE_PATH'), 'ROARING_MODULE_PATH is required')
class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kf-migrate-test-')
        self.addCleanup(self.tmp.cleanup)
        self.log = open(self.tmp.name+'/redis.log', 'w+')
        self.addCleanup(self.log.close)
        self.args = ['redis-server', '--port', '0', '--unixsocket', self.tmp.name+'/redis.sock',
                     '--dir', self.tmp.name, '--save', '', '--appendonly', 'no',
                     '--loadmodule', os.environ['ROARING_MODULE_PATH']]
        self.start()
        self.addCleanup(self.stop)
    def start(self):
        self.proc = subprocess.Popen(self.args, stdout=self.log, stderr=self.log)
        for _ in range(100):
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.connect(self.tmp.name+'/redis.sock')
                self.r = m.Redis.__new__(m.Redis); self.r.sock = sock; self.r.f = sock.makefile('rb')
                self.r.cmd('PING'); return
            except (FileNotFoundError, ConnectionRefusedError): sock.close(); time.sleep(.05)
        raise RuntimeError('Test Redis failed to start')
    def stop(self):
        self.r.close(); self.proc.terminate(); self.proc.wait(timeout=10)
    def seed(self):
        for key in ['bm:like:knowpost:123:0','bm:fav:knowpost:123:1','bm:like:knowpost:123:1099511627776']:
            for bit in (0,7,8,123,32767): self.r.cmd('SETBIT',key,bit,1)
    def test_exact_conversion_dry_run_and_rdb_restart(self):
        self.seed()
        self.assertEqual(m.migrate(self.r)['members'],15)
        self.assertIsNone(self.r.cmd('GET',m.MODE_KEY))
        self.assertEqual(m.scan(self.r,'rbm:*'),set())
        with self.assertRaises(ValueError): m.migrate(self.r,True,False)
        self.assertEqual(m.migrate(self.r,True,True)['shards'],3)
        self.assertEqual(self.r.cmd('GET',m.MODE_KEY),b'roaring')
        self.r.cmd('SAVE'); self.stop(); self.start()
        self.assertEqual(self.r.cmd('R.GETINTARRAY','rbm:like:knowpost:123:0'),[0,7,8,123,32767])
        self.assertEqual(self.r.cmd('GET',m.MODE_KEY),b'roaring')
        with self.assertRaises(ValueError): m.migrate(self.r,True,True)
    def test_aof_rewrite_and_restart(self):
        self.seed(); m.migrate(self.r,True,True)
        self.r.cmd('CONFIG','SET','appendonly','yes')
        for _ in range(200):
            text = self.r.cmd('INFO','persistence').decode()
            if 'aof_rewrite_in_progress:0' in text and 'aof_rewrite_scheduled:0' in text:
                break
            time.sleep(.05)
        else: self.fail('AOF rewrite timeout')
        self.assertIn('aof_last_bgrewrite_status:ok', text)
        self.stop()
        self.args[self.args.index('--appendonly')+1] = 'yes'
        self.start()
        self.assertEqual(self.r.cmd('R.GETINTARRAY','rbm:fav:knowpost:123:1'),[0,7,8,123,32767])
        self.assertEqual(self.r.cmd('GET',m.MODE_KEY),b'roaring')
    def test_resume_and_conflicts(self):
        self.seed(); self.r.cmd('SET',m.MODE_KEY,'migrating')
        self.r.cmd('R.SETINTARRAY','rbm:like:knowpost:123:0',0,7,8,123,32767)
        self.assertEqual(m.migrate(self.r,True,True)['members'],15)
    def test_mismatch_keeps_migration_blocked(self):
        self.seed(); self.r.cmd('R.SETBIT','rbm:like:knowpost:123:0',999,1)
        with self.assertRaises(ValueError): m.migrate(self.r,True,True)
        self.assertEqual(self.r.cmd('GET',m.MODE_KEY),b'migrating')
        self.assertEqual(self.r.cmd('GETBIT','bm:like:knowpost:123:0',123),1)
    def test_ttl_and_oversize_are_rejected(self):
        self.seed(); self.r.cmd('EXPIRE','bm:like:knowpost:123:0',60)
        with self.assertRaises(ValueError): m.migrate(self.r,True,True)
        self.assertIsNone(self.r.cmd('GET',m.MODE_KEY))
        self.r.cmd('PERSIST','bm:like:knowpost:123:0')
        self.r.cmd('SETBIT','bm:like:knowpost:123:0',32768,1)
        with self.assertRaises(ValueError): m.migrate(self.r,True,True)
    def test_empty_database_can_be_initialized(self):
        self.assertEqual(m.migrate(self.r,True,True)['members'],0)
        self.assertEqual(self.r.cmd('GET',m.MODE_KEY),b'roaring')

if __name__ == '__main__': unittest.main()
