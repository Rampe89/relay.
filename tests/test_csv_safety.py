import ast
import unittest
from pathlib import Path

source=Path(__file__).resolve().parents[1].joinpath('app.py').read_text()
node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='csv_safe_cell')
module=ast.Module(body=[node],type_ignores=[])
ns={}
exec(compile(module,'<csv_safe_cell>','exec'),ns)

class CSVSafetyTest(unittest.TestCase):
 def test_formula_prefixes(self):
  for value in ['=1+1','+SUM(A1:A2)','-1+2','@SUM(1)','  =1+1','\t=1+1','\r\n@A1']:
   self.assertEqual(ns['csv_safe_cell'](value),"'"+value)
 def test_regular_values(self):
  for value in ['iPad 10','G0000001','ABC-123','0','']:
   self.assertEqual(ns['csv_safe_cell'](value),value)
 def test_null(self):
  self.assertEqual(ns['csv_safe_cell'](None),'')

if __name__=='__main__':unittest.main()
