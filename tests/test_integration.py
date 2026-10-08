import json, subprocess, tempfile, unittest
from pathlib import Path
DLL=Path(__file__).resolve().parents[1]/'bin/Release/net10.0/VaultTrail.dll'
class VaultTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir();self.store=self.root/'store'
 def tearDown(self):self.temp.cleanup()
 def call(self,*args,ok=True):
  p=subprocess.run(['dotnet',str(DLL),'--store',str(self.store),*map(str,args)],capture_output=True,text=True,encoding='utf-8',timeout=30)
  if ok:self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
  self.assertNotEqual(p.returncode,0);return p
 def snapshot(self):return self.call('snapshot',self.source)['id']
 def test_snapshot_dedup_diff_and_restore(self):
  (self.source/'a.txt').write_text('hello');(self.source/'b.txt').write_text('hello');first=self.snapshot();self.assertEqual(len(list((self.store/'objects').glob('*.blob'))),1)
  (self.source/'a.txt').write_text('changed');(self.source/'b.txt').unlink();(self.source/'new').write_text('new');second=self.snapshot()
  self.assertEqual(self.call('diff',first,second),{'added':['new'],'removed':['b.txt'],'changed':['a.txt']});self.assertTrue(self.call('verify',first)['ok']);self.assertEqual(len(self.call('list')),2)
  target=self.root/'restored';self.call('restore',first,target);self.assertFalse(target.exists());self.call('restore',first,target,'--apply');self.assertEqual((target/'a.txt').read_text(),'hello');self.call('restore',first,target,'--apply',ok=False)
 def test_corruption_blocks_restore(self):
  (self.source/'a').write_text('abc');snap=self.snapshot();obj=next((self.store/'objects').glob('*.blob'));obj.write_text('bad');self.call('verify',snap,ok=False);target=self.root/'out';self.call('restore',snap,target,'--apply',ok=False);self.assertFalse(target.exists())
 def test_reject_traversal_and_nested_store(self):
  (self.source/'a').write_text('a');snap=self.snapshot();mf=self.store/'snapshots'/f'{snap}.json';m=json.loads(mf.read_text());m['Files'][0]['Path']='../escape';mf.write_text(json.dumps(m));self.call('restore',snap,self.root/'out','--apply',ok=False)
  self.store=self.source/'vault';self.call('snapshot',self.source,ok=False)
