import subprocess, os, sys
env = os.environ.copy()
env['PYTHONUTF8'] = '1'
env['PYTHONIOENCODING'] = 'utf-8'
cmd = [r'.venv\Scripts\pysemgrep.exe', 'scan', '--sarif', '--config', 'auto', '--jobs=1', '--quiet', '--no-rewrite-rule-ids', r'C:\Users\Raghul M\Documents\ren3 v2 test']
res = subprocess.run(cmd, env=env, capture_output=True, text=True)
print(res.returncode)
