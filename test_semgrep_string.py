import subprocess, os, sys
env = os.environ.copy()
env["PYTHONUTF8"] = "1"
env["PYTHONIOENCODING"] = "utf-8"
cmd_str = r'".venv\Scripts\pysemgrep.exe" scan --json --config auto "C:\Users\Raghul M\Documents\ren3 v2 test"'
res = subprocess.run(cmd_str, env=env, capture_output=True, text=True, shell=True)
print(res.returncode)
print(len(res.stdout))
