import traceback; from tools.security.semgrep import run_semgrep_scan; 
try:
  print(run_semgrep_scan(r'C:\Users\Raghul M\Documents\ren3 v2 test'))
except Exception as e:
  traceback.print_exc()
