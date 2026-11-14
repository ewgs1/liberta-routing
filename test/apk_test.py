import importlib.util,struct,tempfile,unittest,zipfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('inspect_apk','scripts/inspect-apk.py');apk=importlib.util.module_from_spec(spec);spec.loader.exec_module(apk)
class ApkTests(unittest.TestCase):
 def test_dex_and_resources(self):
  text=b'https://api.tbank.ru/v1\0';data=bytearray(117)+bytes([len(text)-1])+text
  data[:8]=b'dex\n035\0';struct.pack_into('<II',data,56,1,112);struct.pack_into('<I',data,112,117)
  self.assertEqual(apk.dex_strings(data),['https://api.tbank.ru/v1'])
  with tempfile.TemporaryDirectory() as folder:
   path=Path(folder)/'fixture.apk'
   with zipfile.ZipFile(path,'w') as out:out.writestr('classes.dex',data);out.writestr('assets/config.json','{"endpoint":"https://api.2gis.ru/path?hidden=data"}')
   result=apk.inspect(path)
   self.assertEqual([row['domain'] for row in result],['api.2gis.ru','api.tbank.ru'])
   self.assertNotIn('hidden',str(result))
 def test_malformed_dex(self):
  data=bytearray(112);data[:8]=b'dex\n035\0';struct.pack_into('<II',data,56,100,100)
  with self.assertRaises(ValueError):apk.dex_strings(data)
if __name__=='__main__':unittest.main()
