import subprocess, os, sys
env = os.environ.copy()
env['PYTHONUTF8'] = '1'
env['PYTHONIOENCODING'] = 'utf-8'
cmd = [r'.venv\Scripts\pysemgrep.exe', 'scan', '--json', '--config', 'auto', '--jobs=1', '--quiet', '--no-rewrite-rule-ids', r'C:\Users\Raghul M\Documents\ren3 v2 test']
with open(r'c:\tmp\semgrep_stdout.json', 'w') as out_f, open(r'c:\tmp\semgrep_stderr.txt', 'w') as err_f:
  res = subprocess.Popen(cmd, env=env, stdout=out_f, stderr=err_f, creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
  res.wait()
  print(res.returncode)
