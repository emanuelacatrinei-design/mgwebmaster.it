import importlib.util
import unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('build_csp',Path(__file__).with_name('build_csp.py'))
csp=importlib.util.module_from_spec(spec);spec.loader.exec_module(csp)

class CSPTests(unittest.TestCase):
 def test_unknown_script_rejected(self):
  with self.assertRaises(ValueError):csp.transform('<head><script>alert(1)</script></head>')
 def test_unknown_handler_rejected(self):
  with self.assertRaises(ValueError):csp.transform('<head></head><button onclick="alert(1)">Test</button>')
 def test_script_url_rejected(self):
  with self.assertRaises(ValueError):csp.transform('<head></head><a href="javascript:alert(1)">Test</a>')
 def test_demo_never_submits(self):
  result=csp.transform('<head></head><form onsubmit="return false"><input></form>')
  self.assertNotIn('onsubmit=',result);self.assertIn('data-mgw-demo-submit=""',result)
  self.assertIn('/assets/security/demo-submit.js',result)
 def test_json_ld_unchanged(self):
  original='<script type="application/ld+json">{"name":"Demo"}</script>'
  result=csp.transform('<head>'+original+'</head>')
  self.assertIn(original,result);self.assertNotIn('sha256-',result)
 def test_policy_precedes_scripts(self):
  result=csp.transform('<head><meta charset="utf-8"><script src="/script.js"></script></head>')
  self.assertLess(result.index('Content-Security-Policy'),result.index('<script'))
  self.assertNotIn('unsafe-inline',result);self.assertNotIn('unsafe-eval',result)
 def test_reviewed_consent_script_authorized(self):
  import re
  original=(Path(__file__).resolve().parents[1]/'index.html').read_text()
  result=csp.transform(original)
  self.assertIn("T/pE0WPkhsnx7JZTx60ih9qOVOq0EaREjdd6FV2O9Zo=",result)
  self.assertEqual(re.findall(csp.SCRIPT,original),re.findall(csp.SCRIPT,result))

if __name__=='__main__':unittest.main()
